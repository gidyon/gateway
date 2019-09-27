package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Service holds security and discovery information for a micro-service
type Service struct {
	Name        string `yaml:"name"`
	GatewayPath string `yaml:"gatewayPath"`
	Address     string `yaml:"address"`
	Port        int    `yaml:"port"`
	Security    struct {
		TLSKey     string `yaml:"tlsKey"`
		TLSCert    string `yaml:"tlsCert"`
		ServerName string `yaml:"server"`
	}
	client *http.Client
}

// serviceGate contains information about gateway services and internals
type serviceGate struct {
	muxer          *http.ServeMux
	services       map[string]*Service
	servicesFile   string
	redirectStatus int
	development    bool
}

// New creates a service gateway that proxies requests to the most appropriate service in the services entries.
func New(redirectCode int, services []*Service) (h http.Handler, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("panic happened: %v", err1)
		}
	}()

	gw := &serviceGate{
		muxer:          http.NewServeMux(),
		services:       make(map[string]*Service),
		servicesFile:   "",
		redirectStatus: redirectCode,
	}

	gwServices := make(map[string]*Service)

	for _, srv := range services {
		if srv.Name == "" {
			return nil, errors.New("name of service is required")
		}
		gwServices[srv.Name] = &Service{
			Name:        srv.Name,
			GatewayPath: srv.GatewayPath,
			Port:        srv.Port,
		}
		gwServices[srv.Name].Security.TLSCert = srv.Security.TLSCert
		gwServices[srv.Name].Security.TLSKey = srv.Security.TLSKey
		gwServices[srv.Name].Security.ServerName = srv.Security.ServerName
	}

	gw.services = gwServices

	err = gw.updateGateway()
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return nil, nil
}

// NewFromFile creates a service gateway that provies requests to the most appropriate service by reading services configuration from yaml file
func NewFromFile(redirectCode int, servicesFile string) (h http.Handler, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("panic happened: %v", err1)
		}
	}()

	gw := &serviceGate{
		muxer:          http.NewServeMux(),
		services:       make(map[string]*Service),
		servicesFile:   servicesFile,
		redirectStatus: redirectCode,
	}

	// Read the service definitions from YAML
	services, err := readYAML(servicesFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read read YAML")
	}

	gw.services = services

	err = gw.updateGateway()
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, err
}

func (serviceGate *serviceGate) updateGateway() error {
	// Set mode for handling CORS
	mode, ok := os.LookupEnv("MODE")
	if ok {
		mode, err := strconv.ParseBool(mode)
		if err != nil {
			return errors.Wrap(err, "failed to read mode")
		}
		serviceGate.development = mode
	}

	for serviceID, srv := range serviceGate.services {
		var warn bool

		address := strings.TrimPrefix(srv.Address, "https://")
		address = strings.TrimSuffix(address, "/")
		serviceGate.services[serviceID].Address = fmt.Sprintf("https://%s", address)

		gatewayPath := strings.TrimPrefix(srv.GatewayPath, "/")
		serviceGate.services[serviceID].GatewayPath = fmt.Sprintf("/%s", gatewayPath)

		serviceGate.services[serviceID].Name = serviceID

		if srv.GatewayPath == "" {
			return errors.Errorf("service %q: gateway path cannot be empty", serviceID)
		}
		if srv.Address == "" {
			return errors.Errorf("service %q: address cannot be empty", serviceID)
		}
		if srv.Port == 0 {
			warn = true
			serviceGate.services[serviceID].Port = 443
			logrus.Warnf("using default port 443 for service %q", serviceID)
		}
		if srv.Security.TLSCert == "" {
			warn = true
			serviceGate.services[serviceID].Security.TLSCert = "certs/cert.pem"
			logrus.Warnf("using default tls public key for service %q", serviceID)
		}
		if srv.Security.ServerName == "" {
			warn = true
			logrus.Warnf("using default tls server name for service %q", serviceID)
		}

		// Print one line space to separate service warning
		if warn {
			fmt.Println()
		}

		serviceID := serviceID
		err := serviceGate.createHTTPClient(serviceID)
		if err != nil {
			return err
		}

		path := serviceGate.services[serviceID].GatewayPath
		serviceGate.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			serviceGate.do(w, r, serviceID)
		})
	}

	return nil
}

func (serviceGate *serviceGate) createHTTPClient(serviceID string) error {
	srv, ok := serviceGate.services[serviceID]
	if !ok {
		return errors.Errorf("service %q not found", serviceID)
	}

	b, err := ioutil.ReadFile(srv.Security.TLSCert)
	if err != nil {
		return errors.Wrap(err, "FAILED_TO_READ_CERT_FILE")
	}

	// append to cert pool
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		msg := fmt.Sprintf("FAILED_TO_APPEND_CERT: %v", err)
		return errors.New(msg)
	}

	// service client tls
	srvTLS := &tls.Config{
		ServerName:         srv.Security.ServerName,
		RootCAs:            cp,
		InsecureSkipVerify: true,
	}

	// service client transport
	tr := &http.Transport{
		MaxIdleConns:    50,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: srvTLS,
	}

	// set service http client
	serviceGate.services[serviceID].client = &http.Client{Transport: tr}

	return nil
}

func (serviceGate *serviceGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// only set the following headers when mode is development
	if serviceGate.development {
		method := strings.ToLower(r.Method)

		if method == "options" || method == "head" {
			w.Header().Set("access-control-allow-origin", "*")
			w.Header().Set("access-control-allow-methods", "POST, GET, PUT, PATCH, DELETE")
			w.Header().Set("access-control-allow-headers", "Authorization, Content-Type, Mode")
			return
		}
	}

	// call gateway Servemux
	serviceGate.muxer.ServeHTTP(w, r)
}

func (serviceGate *serviceGate) do(w http.ResponseWriter, r *http.Request, serviceID string) {
	srv, ok := serviceGate.services[serviceID]
	if !ok {
		http.Error(w, fmt.Sprintf("service %q not found", serviceID), http.StatusNotFound)
		return
	}

	url := srv.Address + r.URL.Path
	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.Header = r.Header

	res, err := srv.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer res.Body.Close()

	if serviceGate.development {
		w.Header().Set("access-control-allow-origin", r.Header.Get("origin"))
		w.Header().Set("access-control-allow-credentials", "true")
	}

	// update response headers. Important
	for header, vals := range res.Header {
		for _, val := range vals {
			w.Header().Add(header, val)
		}
	}

	w.WriteHeader(res.StatusCode)

	_, err = io.Copy(w, res.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type services struct {
	Services map[string]*Service
}

// reads and parses yaml from file
func readYAML(filename string) (map[string]*Service, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read from file")
	}

	srvs := &services{
		Services: make(map[string]*Service, 0),
	}

	err = yaml.Unmarshal(bs, srvs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal yaml")
	}

	return srvs.Services, nil
}
