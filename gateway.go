package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// a micro-service in a cluster
type service struct {
	Name      string
	URL       string
	Prefix    string
	Resources []string
	TLS       struct {
		Key        string
		Cert       string
		ServerName string `yaml:"server"`
	}
	keywords string
	client   *http.Client
}

// serviceGate contains information about gateway services
type serviceGate struct {
	services       map[string]*service
	servicesFile   string
	redirectStatus int
	development    bool
}

// New creates a service gateway that routes incoming requests to the most appropriate service in a cluster
func New(servicesFile string, redirectCode int) (http.Handler, error) {
	// create gateway
	gw := &serviceGate{
		services:       make(map[string]*service),
		servicesFile:   servicesFile,
		redirectStatus: redirectCode,
	}

	var err error

	// Read the service definitions from YAML
	gw.services, err = readYAML(servicesFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read read YAML")
	}

	for key, srv := range gw.services {
		// Create service tls object
		b, err := ioutil.ReadFile(srv.TLS.Cert)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read cert file")
		}

		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(b) {
			msg := fmt.Sprintf("failed to append certificates: %v", err)
			return nil, errors.New(msg)
		}

		// service client tls
		srvTLS := &tls.Config{
			ServerName:         srv.TLS.ServerName,
			RootCAs:            cp,
			InsecureSkipVerify: true,
		}

		// service client transport
		tr := &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: true,
			TLSClientConfig:    srvTLS,
		}

		// service http client
		gw.services[key].client = &http.Client{Transport: tr}

		// Update keywords
		gw.services[key].keywords = strings.Join(srv.Resources, " ")
	}

	// Set mode for handling CORS
	mode, err := strconv.ParseBool(os.Getenv("MODE"))
	if err != nil {
		return nil, err
	}

	gw.development = mode

	return gw, nil
}

// SetRedirectStatus sets the http redirect code to use
func (services *serviceGate) SetRedirectStatus(code int) {
	services.redirectStatus = code
}

// ServeHTTP serve the request using the right service
func (services *serviceGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Only set the following headers when mode is development
	if services.development {
		method := strings.ToLower(r.Method)

		if method == "options" || method == "head" {
			w.Header().Set("access-control-allow-origin", "*")
			w.Header().Set("access-control-allow-methods", "POST, GET, PUT, PATCH, DELETE")
			w.Header().Set("access-control-allow-headers", "Authorization, Content-Type, Mode")
			return
		}
	}

	keywords := strings.Split(r.Header.Get("keywords"), ",")
	useKeyword := len(keywords) > 1

	for _, srv := range services.services {
		// Route request based on keywords first
		if useKeyword {
			for _, keyword := range keywords {
				if strings.Contains(srv.keywords, keyword) {
					services.do(w, r, srv)
					return
				}
			}
		}
		// Use URL prefix if no keywords match
		if strings.Contains(r.URL.Path, srv.Prefix) {
			services.do(w, r, srv)
			return
		}
	}

	status := http.StatusNotFound

	http.Error(w, "no appropriate service found to route the request to", status)
}

func (services *serviceGate) do(w http.ResponseWriter, r *http.Request, srv *service) {
	url := srv.URL + r.URL.Path
	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Copy all headers as is
	req.Header = r.Header

	// Send request
	res, err := srv.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer res.Body.Close()

	// Only set the following headers when mode is development
	if services.development {
		w.Header().Set("access-control-allow-origin", r.Header.Get("origin"))
		w.Header().Set("access-control-allow-credentials", "true")
	}

	w.WriteHeader(res.StatusCode)

	_, err = io.Copy(w, res.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

type services struct {
	Services map[string]*service
}

// reads and parses yaml from file
func readYAML(filename string) (map[string]*service, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read from file")
	}

	srvs := &services{
		Services: make(map[string]*service, 0),
	}

	err = yaml.Unmarshal(bs, srvs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal yaml")
	}

	return srvs.Services, nil
}
