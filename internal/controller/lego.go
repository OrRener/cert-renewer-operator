package controller

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"strings"

	"net/http"
	"net/url"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/pdns"
	"github.com/go-acme/lego/v4/registration"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey `json:"Key,omitempty"`
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (r *MyUser) SetupLegoClient(User *MyUser, host string) (*lego.Client, error) {

	legoConfig := lego.NewConfig(User)
	legoConfig.CADirURL = fmt.Sprintf("https://%s/dir", host)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048
	legoConfig.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (r *MyUser) SetupPDNS(apiKey, pdnsHost string) (*pdns.DNSProvider, error) {

	config := pdns.NewDefaultConfig()
	config.APIKey = apiKey
	config.ServerName = "localhost"
	host, _ := url.Parse(fmt.Sprintf("http://%s", pdnsHost))
	config.Host = host
	pdnsProvider, err := pdns.NewDNSProviderConfig(config)
	if err != nil {
		return nil, err
	}
	return pdnsProvider, nil
}

func (r *MyUser) RegisterClient(User *MyUser, client *lego.Client) error {
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	User.Registration = reg
	return nil
}

func (r *MyUser) SetDNSProvider(client *lego.Client, pdnsProvider *pdns.DNSProvider) error {
	err := client.Challenge.SetDNS01Provider(pdnsProvider, dns01.CondOption(
		true, dns01.AddRecursiveNameservers([]string{"pdns:53"}),
	))
	if err != nil {
		return err
	}
	return nil
}

func (r *MyUser) ObtainCertificates(client *lego.Client, domains []string) ([]byte, []byte, error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		for isDNS403(err) {
			certificates, err = client.Certificate.Obtain(request)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return certificates.Certificate, certificates.PrivateKey, nil
}

func isDNS403(err error) bool {
	return err != nil && strings.Contains(err.Error(), "urn:ietf:params:acme:error:unauthorized")
}
