package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/linode/linodego"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
)

const (
	StagingDirectory    = "https://acme-staging.api.letsencrypt.org/directory"
	ProductionDirectory = "https://acme-v01.api.letsencrypt.org/directory"
)

func periodicallyRenew(ctx context.Context, frequency time.Duration, manager *autocert.Manager, linode linodego.Client, balancerNameOrID, domain string, production, init bool) {
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}
	if init {
		log.Println("performing an initial renewal in 30 seconds...")
		time.Sleep(30 * time.Second) // to give the balancer some time to see that we're up
		renew(ctx, frequency, manager, linode, balancerNameOrID, domain, production, hello)
	}

	ticker := time.NewTicker(frequency)
	log.Printf("next renewal scheduled for %s", time.Now().Add(frequency).Format(time.Stamp))
	for t := range ticker.C {
		renew(ctx, frequency, manager, linode, balancerNameOrID, domain, production, hello)
		log.Printf("next renewal scheduled for %s", t.Add(frequency).Format(time.Stamp))
	}
}

func renew(ctx context.Context, frequency time.Duration, manager *autocert.Manager, linode linodego.Client, balancerNameOrID, domain string, production bool, hello *tls.ClientHelloInfo) {
	log.Println("renewing certificate for " + hello.ServerName)
	cert, err := manager.GetCertificate(hello)
	if err != nil {
		log.Printf("failed to renew certificate: %s", err)
		return
	}

	certText, err := getCertText(cert)
	if err != nil {
		log.Printf("failed to get certificate text: %s", err)
		return
	}

	keyText, err := getKeyText(cert)
	if err != nil {
		log.Printf("failed to get key text: %s", err)
		return
	}

	log.Printf("got certificate:\n%s", certText)

	if !production {
		log.Printf("got key:\n%s", keyText)
	}

	log.Println("saving certificate to nodebalancer config")
	if err = save(ctx, linode, balancerNameOrID, certText, keyText); err != nil {
		log.Printf("failed to save certificate: %s", err)
		return
	}

	log.Println("certificate updated for balancer " + balancerNameOrID)
}

func getCertText(cert *tls.Certificate) (string, error) {
	var builder strings.Builder
	for _, part := range cert.Certificate {
		if err := pem.Encode(&builder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: part,
		}); err != nil {
			return "", errors.New("failed to pem-encode certificate: " + err.Error())
		}
	}
	return builder.String(), nil
}

func getKeyText(cert *tls.Certificate) (string, error) {
	switch t := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		var builder strings.Builder
		if err := pem.Encode(&builder, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		}); err != nil {
			return "", errors.New("failed to pem-encode key: " + err.Error())
		}
		return builder.String(), nil

	default:
		return "", fmt.Errorf("unknown private key type: %T", cert.PrivateKey)
	}
}

func save(ctx context.Context, linode linodego.Client, balancerNameOrID, certText, keyText string) error {
	balancer, err := findNodeBalancer(ctx, linode, balancerNameOrID)
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
			Port:    443,
			SSLCert: certText,
			SSLKey:  keyText,
		}); err != nil {
			return errors.New("failed to update node balancer config: " + err.Error())
		}
	}

	return nil
}

func findNodeBalancer(ctx context.Context, linode linodego.Client, nameOrID string) (*linodego.NodeBalancer, error) {
	balancers, err := linode.ListNodeBalancers(ctx, nil)
	if err != nil {
		return nil, errors.New("failed to list node balancers: " + err.Error())
	}
	id, _ := strconv.Atoi(nameOrID)
	for _, balancer := range balancers {
		if (id != 0 && balancer.ID == id) || (id == 0 && *balancer.Label == nameOrID) {
			return &balancer, nil
		}
	}
	return nil, nil
}

func findNodeBalancerConfig(ctx context.Context, linode linodego.Client, balancer *linodego.NodeBalancer) (*linodego.NodeBalancerConfig, error) {
	configs, err := linode.ListNodeBalancerConfigs(ctx, balancer.ID, nil)
	if err != nil {
		return nil, errors.New("failed to list node balancer configs: " + err.Error())
	}
	for _, config := range configs {
		if config.Port == 443 {
			return &config, nil
		}
	}
	return nil, nil
}

func createLinodeClient(token string) linodego.Client {
	return linodego.NewClient(&http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
		},
	})
}

func redirect(addr string) http.Handler {
	target := "https://" + addr
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
}

func parseBool(v string) bool {
	b, _ := strconv.ParseBool(v)
	return b
}

func makeManager(domain, email, cacheDir string, production bool) *autocert.Manager {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
		Client:     &acme.Client{},
	}
	if cacheDir != "" {
		manager.Cache = autocert.DirCache(cacheDir)
	}
	if production {
		log.Println("running in PRODUCTION")
		manager.Client.DirectoryURL = ProductionDirectory
	} else {
		log.Println("running in STAGING")
		manager.Client.DirectoryURL = StagingDirectory
	}
	return manager
}

func main() {
	var (
		ctx              = context.Background()
		frequencyString  = flag.String("frequency", os.Getenv("FREQUENCY"), "how often to attempt certificate renewal, in a form understandable by https://golang.org/pkg/time/#ParseDuration")
		balancerNameOrID = flag.String("balancer", os.Getenv("BALANCER"), "id or label of the NodeBalancer to update")
		linodeToken      = flag.String("linode-token", os.Getenv("LINODE_TOKEN"), "Linode API token")
		email            = flag.String("email", os.Getenv("EMAIL"), "email used for the renewal process")
		domain           = flag.String("domain", os.Getenv("DOMAIN"), "domain to renew")
		port             = flag.String("port", os.Getenv("PORT"), "port for the HTTP challenge handler to listen on")
		cacheDir         = flag.String("cache-dir", os.Getenv("CACHE_DIR"), "autocert cache directory (optional)")
		production       = flag.Bool("production", parseBool(os.Getenv("PRODUCTION")), "set to true to run against the production Let's Encrypt endpoint (defaults to staging)")
		init             = flag.Bool("init", parseBool(os.Getenv("INIT")), "set to true to do an initial run before switching to a regular interval (defaults to false)")
	)
	flag.Parse()

	if *frequencyString == "" || *balancerNameOrID == "" || *linodeToken == "" || *email == "" || *port == "" || *domain == "" {
		flag.Usage()
		os.Exit(1)
	}

	frequency, err := time.ParseDuration(*frequencyString)
	if err != nil {
		log.Fatalf("coudln't parse frequency '%s': %s", *frequencyString, err)
	}

	linode := createLinodeClient(*linodeToken)
	manager := makeManager(*domain, *email, *cacheDir, *production)

	go periodicallyRenew(ctx, frequency, manager, linode, *balancerNameOrID, *domain, *production, *init)

	log.Println("listening on port " + *port)
	fallback := redirect(*domain)
	if err := http.ListenAndServe(":"+*port, manager.HTTPHandler(fallback)); err != nil {
		log.Fatal(err)
	}
}
