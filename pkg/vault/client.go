package vault

import (
	"fmt"
	log "github.com/aarnaud/vault-pki-mon/pkg/logger"
	jwtauth "github.com/hashicorp/vault-plugin-auth-jwt"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"os"
	"time"
)

type secretCallback func(secret *vaultapi.Secret)
type secretKV2Callback func(secret *KV_version2)
type ClientWrapper struct {
	Client *vaultapi.Client
}

type KV_version2 struct {
	Data     map[string]interface{} `json:"data"`
	Metadata map[string]interface{} `json:"metadata"`
}

type SecretList struct {
	Keys []string
}

type SecretCertificate struct {
	Certificate     string
	Revocation_time int64
}

func (vault *ClientWrapper) Init() {
	var err error

	vaultconf := &vaultapi.Config{}
	err = vaultconf.ReadEnvironment()
	if err != nil {
		log.Fatalln(err.Error())
	}

	vault.Client, err = vaultapi.NewClient(vaultconf)
	if err != nil {
		log.Fatal("[vault] ", err)
	}

	if vault.Client.Token() == "" {
		if os.Getenv("VAULT_AUTH_METHOD") == "oidc" {
			vault.authOIDC()
		}
	}

	token_secret, err := vault.Client.Auth().Token().LookupSelf()
	if err != nil {
		log.Fatal("[vault] ", err)
	}
	ttl, _ := token_secret.TokenTTL()

	log.Infof("Token TTL: %d  LeaseDuration: %d", int32(ttl/time.Second), token_secret.LeaseDuration)

	isRenewable, _ := token_secret.TokenIsRenewable()
	if isRenewable {
		// Get a renewed token
		secret, err := vault.Client.Auth().Token().RenewTokenAsSelf(vault.Client.Token(), 0)
		if err != nil {
			log.Fatal("[vault] ", err)
		}

		token_renewer, err := vault.Client.NewRenewer(&vaultapi.RenewerInput{
			Secret: secret,
		})
		if err != nil {
			log.Fatal("[vault] ", err)
		}

		watch_renewer_vault(token_renewer)
	} else {
		ttl, _ := token_secret.TokenTTL()
		log.Infof("[vault] token is not renewable, ttl: %d", int32(ttl/time.Second))
	}
}

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
		renewer, err := vault.Client.NewRenewer(&vaultapi.RenewerInput{
			Secret: secret,
		})
		if err != nil {
			log.Fatal("[vault] ", err)
		}

		watch_renewer_vault(renewer)
	} else {
		log.Infof("[vault] secret is not renewable, use TTL to refresh secret : %s", path)
		// Refresh secret at the end of Lease
		if secret.LeaseDuration > 0 {
			go func() {
				for {
					time.Sleep(time.Duration(secret.LeaseDuration) * time.Second)
					secret, err = vault.Client.Logical().Read(path)
					if err != nil {
						log.Errorln("[vault]", err)
						continue
					}
					if secret == nil {
						log.Errorln("[vault] secret not found : %s", path)
						continue
					}
					fn(secret)
					log.Infof("[vault] successfully refreshed : %s", path)
				}
			}()
		}
	}
	return nil
}

func (vault *ClientWrapper) GetSecretKV2(path string, fn secretKV2Callback) error {
	var secret_kv2 = &KV_version2{}
	return vault.GetSecret(path, func(secret *vaultapi.Secret) {
		err := mapstructure.WeakDecode(secret.Data, secret_kv2)
		if err != nil {
			log.Errorln("Can decode secret as KV version 2 ", err)
		}
		fn(secret_kv2)
	})
}

func watch_renewer_vault(renewer *vaultapi.Renewer) {
	go func() {
		for {
			select {
			case err := <-renewer.DoneCh():
				if err != nil {
					log.Fatal("[vault]", err)
				}

				// Renewal is now over
			case renewal := <-renewer.RenewCh():
				var flag string
				flag = renewal.Secret.LeaseID
				if flag == "" {
					flag = "token"
				}
				log.Infof("[vault] successfully renewed: %s", flag)
				// LeaseDuration=0 => infinte time but if LeaseDuration < 10s secret wasn't renewed
				// Strange because Renewable is true
				if renewal.Secret.LeaseDuration < 10 && renewal.Secret.LeaseDuration != 0 {
					log.Fatalf("[vault] not renewable anymore: %s", flag)
					renewer.Stop()
					break
				}
			}
		}
	}()
	go func() {
		for {
			// Prevent loop when secret wasn't renewed before expiration
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
		log.Fatalln(err.Error())
	}
	if secret == nil || secret.Auth == nil {
		log.Fatalln("Failed to auth with OIDC")
	}
	vault.Client.SetToken(secret.Auth.ClientToken)
}
