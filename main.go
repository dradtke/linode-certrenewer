package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/linode/linodego"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
)

const (
	RenewalDuration = 24 * time.Hour
	Host            = "damienradtke.com"
	BalancerName    = "damienradtkecom"
	LinodeToken     = "af53c271d591561eec8c78e88830fbac2c102e0f36796745ac3ff0fb442c7ebd"
)

var manager = autocert.Manager{
	Prompt:     autocert.AcceptTOS,
	Cache:      autocert.DirCache(os.Getenv("NOMAD_SECRETS_DIR")),
	HostPolicy: autocert.HostWhitelist(Host, "www."+Host),
	Email:      "me@damienradtke.com",
}

func periodicallyRenew() {
	for range time.NewTicker(RenewalDuration).C {
		renewAndSave(context.Background())
	}
}

func renewAndSave(ctx context.Context) {
	log.Println("renewing certificate")
	cert, err := renew()
	if err != nil {
		log.Printf("failed to renew certificate: %s", err)
		return
	}

	certText, err := getCertText(cert)
	if err != nil {
		log.Printf("failed to marshal certificate: %s", err)
		return
	}

	keyText, err := getKeyText(cert)
	if err != nil {
		log.Printf("failed to marshal key: %s", err)
		return
	}

	log.Println("saving certificate to nodebalancer config")
	if err = save(ctx, certText, keyText); err != nil {
		log.Printf("failed to save certificate: %s", err)
		return
	}

	log.Println("certificate updated for " + BalancerName)
}

func renew() (*tls.Certificate, error) {
	return manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: Host,
	})
}

func getCertText(cert *tls.Certificate) (string, error) {
	var builder strings.Builder
	for _, part := range cert.Certificate {
		if err := pem.Encode(&builder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: part,
		}); err != nil {
			return "", err
		}
	}
	return builder.String(), nil
}

func getKeyText(cert *tls.Certificate) (string, error) {
	switch t := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		v := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		})
		return string(v), nil

	default:
		return "", fmt.Errorf("unknown private key type: %T", cert.PrivateKey)
	}
}

func save(ctx context.Context, certText, keyText string) error {
	linode := createLinodeClient(LinodeToken)

	balancer, err := findNodeBalancer(ctx, linode, BalancerName)
	if err != nil {
		return errors.New("failed to find node balancer: " + err.Error())
	}

	config, err := findNodeBalancerConfig(ctx, linode, balancer)
	if err != nil {
		return errors.New("failed to find node balancer config: " + err.Error())
	}

	if config == nil {
		log.Println("creating new node balancer config")
		if _, err := linode.CreateNodeBalancerConfig(ctx, balancer.ID, linodego.NodeBalancerConfigCreateOptions{
			Port:       443,
			Protocol:   linodego.ProtocolHTTPS,
			Algorithm:  linodego.AlgorithmRoundRobin,
			Stickiness: linodego.StickinessNone,
			Check:      linodego.CheckNone,
			SSLCert:    certText,
			SSLKey:     keyText,
		}); err != nil {
			return errors.New("failed to create new node balancer config: " + err.Error())
		}
	} else {
		if _, err = linode.UpdateNodeBalancerConfig(ctx, balancer.ID, config.ID, linodego.NodeBalancerConfigUpdateOptions{
			SSLCert: certText,
			SSLKey:  keyText,
		}); err != nil {
			return errors.New("failed to update node balancer config: " + err.Error())
		}
	}

	return nil
}

func findNodeBalancer(ctx context.Context, linode linodego.Client, name string) (linodego.NodeBalancer, error) {
	balancers, err := linode.ListNodeBalancers(ctx, nil)
	if err != nil {
		return linodego.NodeBalancer{}, err
	}
	for _, balancer := range balancers {
		if *balancer.Label == name {
			return balancer, nil
		}
	}
	return linodego.NodeBalancer{}, errors.New("not found")
}

func findNodeBalancerConfig(ctx context.Context, linode linodego.Client, balancer linodego.NodeBalancer) (*linodego.NodeBalancerConfig, error) {
	configs, err := linode.ListNodeBalancerConfigs(ctx, balancer.ID, nil)
	if err != nil {
		return nil, err
	}
	for _, config := range configs {
		if config.Port == 443 {
			return &config, nil
		}
	}
	return nil, nil
}

func createLinodeClient(token string) linodego.Client {
	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
		},
	}
	return linodego.NewClient(oauth2Client)
}

func fallback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://damienradtke.com/", http.StatusFound)
}

func main() {
	go periodicallyRenew()
	var port = os.Getenv("NOMAD_PORT_http")
	log.Println("listening on port " + port)
	if err := http.ListenAndServe(":"+port, manager.HTTPHandler(http.HandlerFunc(fallback))); err != nil {
		log.Fatal(err)
	}
}
