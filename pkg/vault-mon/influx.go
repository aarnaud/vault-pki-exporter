package vault_mon

import (
	"fmt"
	influx "github.com/influxdata/influxdb1-client"
	"strings"
	"time"
)

//var labelNames = []string{
//	"source",
//	"serial",
//	"common_name",
//	"organization",
//	"organizational_unit",
//	"country",
//	"province",
//	"locality",
//}
//
//type PromMetrics struct {
//	expiry    *prometheus.GaugeVec
//	age       *prometheus.GaugeVec
//	startdate *prometheus.GaugeVec
//	enddate   *prometheus.GaugeVec
//}

func InfluxWatchCerts(pkimon *PKIMon) {
	go func() {
		for {
			for pkiname, pki := range pkimon.GetPKIs() {
				for _, cert := range pki.GetCerts() {
					now := time.Now()
					point := influx.Point{
						Measurement: "x509cert",
						Tags: map[string]string{
							"source":              pkiname,
							"serial":              strings.ReplaceAll(fmt.Sprintf("% x", cert.SerialNumber.Bytes()), " ", "-"),
							"common_name":         cert.Subject.CommonName,
							"organization":        getEmptyStringIfEmpty(cert.Subject.Organization),
							"organizational_unit": getEmptyStringIfEmpty(cert.Subject.OrganizationalUnit),
							"country":             getEmptyStringIfEmpty(cert.Subject.Country),
							"province":            getEmptyStringIfEmpty(cert.Subject.Province),
							"locality":            getEmptyStringIfEmpty(cert.Subject.Locality),
						},
						Fields: map[string]interface{}{
							"expiry":    int(cert.NotAfter.Sub(now).Seconds()),
							"age":       int(now.Sub(cert.NotBefore).Seconds()),
							"startdate": int(cert.NotBefore.Unix()),
							"enddate":   int(cert.NotAfter.Unix()),
						},
						Time:      time.Now(),
						Precision: "s",
					}
					fmt.Println(point.MarshalString())
				}
			}
			time.Sleep(time.Second)
		}
	}()

}
