package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	ExitCodeOK = iota
	ExitCodeParseFlagError
	ExitCodeNotExsistsDomainError
	ExitCodeCheckFalseError
)

type CLI struct {
	outStream io.Writer
	errStream io.Writer
}

func (c *CLI) Run(args []string) int {
	var domain string
	flags := flag.NewFlagSet("tls-checker", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.StringVar(&domain, "domain", "", "check domain")

	if err := flags.Parse(args[1:]); err != nil {
		return ExitCodeParseFlagError
	}

	if domain == "" {
		fmt.Fprintf(c.errStream, "Need Domain\n")
		return ExitCodeNotExsistsDomainError
	}

	fmt.Fprintf(c.outStream, "Domain: %s\n", domain)
	result, err := checkDomain(domain)
	if err != nil {
		fmt.Fprintf(c.errStream, err.Error())
		return ExitCodeCheckFalseError
	}

	fmt.Fprintf(c.outStream, "CipherSuites:\n")
	for _, cs := range result.SslConfig.CipherSuites {
		fmt.Fprintf(c.outStream, "  - %s\n", cs)
	}
	return ExitCodeOK
}

func checkDomain(domain string) (*TLSStatus, error) {
	u, _ := url.Parse("https://cryptoreport.geotrust.com/chainTester/webservice/validatecerts/json")
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("domain", domain)
	q.Add("port", "443")
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	client.Timeout = 60 * time.Second

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("API result failed: %s", resp.Status)
	}
	defer resp.Body.Close()

	result := &TLSStatus{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}

func main() {
	cli := &CLI{
		outStream: os.Stdout,
		errStream: os.Stderr,
	}

	os.Exit(cli.Run(os.Args))
}

type TLSStatus struct {
	HostName    string `json:"hostName"`
	CertAlgList []struct {
		Codes     []string `json:"codes"`
		Algorithm string   `json:"algorithm"`
		CertList  []struct {
			CertType             string   `json:"certType"`
			IssuedByOrg          []string `json:"issuedByOrg"`
			IssuedByCommonName   []string `json:"issuedByCommonName"`
			IssuedByCountry      []string `json:"issuedByCountry"`
			SerialNumberHex      string   `json:"serialNumberHex"`
			FetchType            string   `json:"fetchType"`
			RevocationCheckModel struct {
				OcspCheck struct {
					OcspCheckStatus string      `json:"ocspCheckStatus"`
					OcspStatus      string      `json:"ocspStatus"`
					Reason          interface{} `json:"reason"`
				} `json:"ocspCheck"`
				CrlCheck interface{} `json:"crlCheck"`
			} `json:"revocationCheckModel,omitempty"`
			ProductType       string   `json:"productType"`
			SctPresent        int      `json:"sctPresent"`
			O                 []string `json:"O"`
			OU                []string `json:"OU,omitempty"`
			CN                []string `json:"CN"`
			L                 []string `json:"L,omitempty"`
			C                 []string `json:"C"`
			S                 []string `json:"S,omitempty"`
			ValidFrom         string   `json:"validFrom"`
			ValidTo           string   `json:"validTo"`
			SigAlg            string   `json:"sigAlg"`
			KeyLength         string   `json:"keyLength"`
			SanList           string   `json:"sanList,omitempty"`
			RevocationDetails struct {
				Method string      `json:"method"`
				Status string      `json:"status"`
				Reason interface{} `json:"reason"`
			} `json:"revocationDetails,omitempty"`
			IssuedByOrgUnit []string `json:"issuedByOrgUnit,omitempty"`
		} `json:"certList"`
	} `json:"certAlgList"`
	ServerCertAlgList []struct {
		Algorithm string `json:"algorithm"`
		CertList  []struct {
			IssuedByOrg        []string `json:"issuedByOrg"`
			IssuedByCommonName []string `json:"issuedByCommonName"`
			IssuedByCountry    []string `json:"issuedByCountry"`
			SerialNumberHex    string   `json:"serialNumberHex"`
			ProductType        string   `json:"productType"`
			SctPresent         int      `json:"sctPresent"`
			O                  []string `json:"O"`
			OU                 []string `json:"OU,omitempty"`
			CN                 []string `json:"CN"`
			L                  []string `json:"L,omitempty"`
			C                  []string `json:"C"`
			S                  []string `json:"S,omitempty"`
			ValidFrom          string   `json:"validFrom"`
			ValidTo            string   `json:"validTo"`
			SigAlg             string   `json:"sigAlg"`
			KeyLength          string   `json:"keyLength"`
			SanList            string   `json:"sanList,omitempty"`
			IssuedByOrgUnit    []string `json:"issuedByOrgUnit,omitempty"`
		} `json:"certList"`
	} `json:"serverCertAlgList"`
	SslConfig struct {
		CipherSuites              []string `json:"cipherSuites"`
		PortNumber                int      `json:"portNumber"`
		IPAddress                 string   `json:"ipAddress"`
		HTTPServerSignature       string   `json:"httpServerSignature"`
		ServerName                string   `json:"serverName"`
		Hsts                      string   `json:"hsts"`
		Heartbleed                bool     `json:"heartbleed"`
		Poodle                    bool     `json:"poodle"`
		Poodletls                 bool     `json:"poodletls"`
		Freak                     bool     `json:"freak"`
		Beast                     bool     `json:"beast"`
		Crime                     bool     `json:"crime"`
		Npn                       bool     `json:"npn"`
		SecureRenegotiation       bool     `json:"secureRenegotiation"`
		DowngradeAttackPrevention string   `json:"downgradeAttackPrevention"`
		SessionTickets            bool     `json:"sessionTickets"`
		SessionCache              bool     `json:"sessionCache"`
		Protocols                 struct {
			Sslv2Status  bool `json:"sslv2Status"`
			Sslv3Status  bool `json:"sslv3Status"`
			Tlsv1Status  bool `json:"tlsv1Status"`
			Tlsv11Status bool `json:"tlsv1_1Status"`
			Tlsv12Status bool `json:"tlsv1_2Status"`
		} `json:"Protocols"`
		CompressionStatus  bool `json:"compressionStatus"`
		Rc4Status          bool `json:"rc4Status"`
		HeartbeatStatus    bool `json:"heartbeatStatus"`
		OcspStaplingStatus bool `json:"ocspStaplingStatus"`
	} `json:"sslConfig"`
}
