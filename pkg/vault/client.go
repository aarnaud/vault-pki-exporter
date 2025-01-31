package vault

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aarnaud/vault-pki-exporter/pkg/logger"
	jwtauth "github.com/hashicorp/vault-plugin-auth-jwt"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/mitchellh/mapstructure"
)

type secretCallback func(secret *vaultapi.Secret)
type secretKV2Callback func(secret *KVVersion2)

// ClientWrapper wraps around vaultapi client
type ClientWrapper struct {
	Client *vaultapi.Client
}

// KVVersion2 is Vault's newer API version structure
type KVVersion2 struct {
	Data     map[string]interface{} `json:"data"`
	Metadata map[string]interface{} `json:"metadata"`
}

// SecretList is a list of keys
type SecretList struct {
	Keys []string
}

// SecretCertificate is an object of the actual certificate we obtain from Vault
type SecretCertificate struct {
	Certificate    string
	RevocationTime int64
}

// Init makes a new Vault Client Wrapper
func (vault *ClientWrapper) Init() {
	var err error

	vaultconf := &vaultapi.Config{}
	err = vaultconf.ReadEnvironment()
	if err != nil {
		logger.SlogFatal("Failed to read Vault environment", "error", err)
	}

	vault.Client, err = vaultapi.NewClient(vaultconf)
	if err != nil {
		logger.SlogFatal("[vault] Error creating new client", err)
	}

	if vault.Client.Token() == "" {
		switch os.Getenv("VAULT_AUTH_METHOD") {
		case "oidc":
			vault.authOIDC()
		case "k8s":
			vault.authK8S()
		}
	}

	tokenSecret, err := vault.Client.Auth().Token().LookupSelf()
	if err != nil {
		logger.SlogFatal("[vault] Error getting a new token", err)
	}
	ttl, _ := tokenSecret.TokenTTL()

	slog.Info("Token TTL and LeaseDuration", "ttl", int32(ttl/time.Second), "lease_duration", tokenSecret.LeaseDuration)

	isRenewable, _ := tokenSecret.TokenIsRenewable()
	if isRenewable {
		// Get a renewed token
		secret, err := vault.Client.Auth().Token().RenewTokenAsSelf(vault.Client.Token(), 0)
		if err != nil {
			logger.SlogFatal("[vault] Error renewing token", err)
		}

		tokenRenewer, err := vault.Client.NewLifetimeWatcher(&vaultapi.RenewerInput{
			Secret: secret,
		})
		if err != nil {
			logger.SlogFatal("[vault] Error renewing token", err)
		}

		watchRenewerVault(tokenRenewer)
	} else {
		ttl, _ := tokenSecret.TokenTTL()
		slog.Info("[vault] token is not renewable", "ttl", int32(ttl/time.Second))
	}
}

// GetSecret finds the secrets to authenticate with Vault
func (vault *ClientWrapper) GetSecret(path string, fn secretCallback) error {
	var secret *vaultapi.Secret
	var err error
	secret, err = vault.Client.Logical().Read(path)
	if err != nil {
		return err
	}
	if secret == nil {
		return fmt.Errorf("secret not found : %s", path)
	}
	// return the secret
	fn(secret)

	if secret.Renewable {
		renewer, err := vault.Client.NewLifetimeWatcher(&vaultapi.RenewerInput{
			Secret: secret,
		})
		if err != nil {
			logger.SlogFatal("[vault] Error renewing token", err)
		}

		watchRenewerVault(renewer)
	} else {
		slog.Info("[vault] secret is not renewable, use TTL to refresh secret", "path", path)
		// Refresh secret at the end of Lease
		if secret.LeaseDuration > 0 {
			go func() {
				for {
					slog.Info("Sleeping before refreshing vault", "interval", time.Duration(secret.LeaseDuration))
					time.Sleep(time.Duration(secret.LeaseDuration) * time.Second)
					secret, err = vault.Client.Logical().Read(path)
					if err != nil {
						slog.Error("[vault]", "error", err)
						continue
					}
					if secret == nil {
						slog.Error("[vault] secret not found", "path", path)
						continue
					}
					fn(secret)
					slog.Info("[vault] successfully refreshed", "path", path)
				}
			}()
		}
	}
	return nil
}

// GetSecretKV2 gets the Vault auth secret for the KV2 API
func (vault *ClientWrapper) GetSecretKV2(path string, fn secretKV2Callback) error {
	var secretKv2 = &KVVersion2{}
	return vault.GetSecret(path, func(secret *vaultapi.Secret) {
		err := mapstructure.WeakDecode(secret.Data, secretKv2)
		if err != nil {
			slog.Error("Cannot decode secret for KV version 2", "error", err)
		}
		fn(secretKv2)
	})
}

func watchRenewerVault(renewer *vaultapi.Renewer) {
	go func() {
		for {
			select {
			case err := <-renewer.DoneCh():
				if err != nil {
					logger.SlogFatal("[vault] Error renewing token", err)
				}

				// Renewal is now over
			case renewal := <-renewer.RenewCh():
				var flag string
				flag = renewal.Secret.LeaseID
				if flag == "" {
					flag = "token"
				}
				slog.Info("[vault] successfully renewed", "lease_id", flag)
				// LeaseDuration=0 => infinte time but if LeaseDuration < 10s secret wasn't renewed
				// Strange because Renewable is true
				if renewal.Secret.LeaseDuration < 10 && renewal.Secret.LeaseDuration != 0 {
					logger.SlogFatal("[vault] Not renewable anymore", flag)
					renewer.Stop()
					break
				}
			}
		}
	}()
	go func() {
		for {
			// Prevent loop when secret wasn't renewed before expiration
			slog.Info("Waiting before calling another renew", "interval", time.Second)
			time.Sleep(time.Second)
			renewer.Renew()
		}
	}()
}

func (vault *ClientWrapper) authOIDC() {
	var err error
	mount := os.Getenv("VAULT_AUTH_MOUNT")
	if mount == "" {
		mount = "oidc"
	}

	jwthandler := new(jwtauth.CLIHandler)
	data := make(map[string]string)
	data["mount"] = mount
	secret, err := jwthandler.Auth(vault.Client, data)
	if err != nil {
		logger.SlogFatal("[vault] Error authing to Vault", err)
	}
	if secret == nil || secret.Auth == nil {
		logger.SlogFatal("[vault] Failed to auth with OIDC")
	}
	vault.Client.SetToken(secret.Auth.ClientToken)
}

func (vault *ClientWrapper) authK8S() {
	mount := os.Getenv("VAULT_AUTH_MOUNT")
	if mount == "" {
		mount = "kubernetes"
	}

	am, err := kubernetes.NewKubernetesAuth(os.Getenv("VAULT_K8S_ROLE"), kubernetes.WithMountPath(mount))
	if err != nil {
		logger.SlogFatal("Failed to create k8s auth method", err)
	}
	if _, err := vault.Client.Auth().Login(context.Background(), am); err != nil {
		logger.SlogFatal("Failed to auth with k8s", err)
	}
}
