package acmedns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

type AcmeDnsCredentials struct {
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
}

type Provider struct {
	CredentialsFile string `json:"credentials_file,omitempty"`
	ClientURL       string `json:"client_url,omitempty"`
	Credentials     AcmeDnsCredentials
}

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.acmedns",
		New: func() caddy.Module { return new(Provider) },
	}
}

func (p *Provider) Provision(ctx caddy.Context) error {
	p.Credentials.Password = caddy.NewReplacer().ReplaceAll(p.Credentials.Password, "")
	var credentials AcmeDnsCredentials
	file, err := ioutil.ReadFile(p.CredentialsFile)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(file), &credentials)
	if err != nil {
		return err
	}
	if credentials.Username == "" {
		return fmt.Errorf("missing username in account config")
	}
	if credentials.Password == "" {
		return fmt.Errorf("missing password in account config")
	}
	if credentials.Subdomain == "" {
		return fmt.Errorf("missing subdomain in account config")
	}
	p.Credentials = credentials
	return nil
}

func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "credentials_file":
				if p.CredentialsFile != "" {
					return d.Err("credentials file already set")
				}
				if d.NextArg() {
					p.CredentialsFile = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "client_url":
				if p.CredentialsFile != "" {
					return d.Err("client_url already set")
				}
				if d.NextArg() {
					p.ClientURL = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.CredentialsFile == "" {
		return d.Err("missing credentials_file")
	}
	if p.ClientURL == "" {
		return d.Err("missing client_url")
	}
	return nil
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	fmt.Printf("ZONE = %s\nRECORDS = %v", zone, recs)

	for _, record := range recs {
		if record.Type != "TXT" {
			fmt.Println("Record", record.Type)
			return nil, fmt.Errorf("acme-dns only supports changing TXT records")
		}
		body, err := json.Marshal(
			map[string]string{
				"subdomain": p.Credentials.Subdomain,
				"txt":       record.Value,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal JSON")
		}
		req, err := http.NewRequest("POST", p.ClientURL+"/update", bytes.NewBuffer(body))
		req.Header.Set("X-Api-User", p.Credentials.Username)
		req.Header.Set("X-Api-Key", p.Credentials.Password)
		client := &http.Client{Timeout: time.Second * 10}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Error reading response. %s", err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("Error: response code %d while registering acme-dns account", resp.StatusCode)
		}
	}
	return recs, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("acme-dns does not support record deletion")
}

var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
