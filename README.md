# Linode Cert Renewer

This repository contains a program for periodically renewing SSL certificates
for a domain, and writing the result to a Linode NodeBalancer. It is intended to
be run alongside a node-balanced service whose SSL is terminated at the
NodeBalancer.

Usage:

```bash
Usage of cert-renewer:
  -balancer string
        id or label of the NodeBalancer to update
  -cache-dir string
        autocert cache directory (optional)
  -domain string
        domain to renew
  -email string
        email used for the renewal process
  -frequency string
        how often to attempt certificate renewal, in a form understandable by https://golang.org/pkg/time/#ParseDuration
  -init
        set to true to do an initial run before switching to a regular interval (defaults to false)
  -linode-token string
        Linode API token
  -port string
        port for the HTTP challenge handler to listen on
  -production
        set to true to run against the production Let's Encrypt endpoint (defaults to staging)
```

Each value can also be set by an environment variable of the same name, e.g.
`-linode-token` can instead be specified via the variable `LINODE_TOKEN`.
