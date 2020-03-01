package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

type bufferPool interface {
	Get() []byte
	Put([]byte)
}

type gatewayBufferPool struct {
	pool *sync.Pool
}

// newBufferPool creates a bytes pool to be used by httputil reverse proxy while copying response
func newBufferPool() httputil.BufferPool {
	return &gatewayBufferPool{
		pool: &sync.Pool{
			New: func() interface{} {
				mem := make([]byte, 32*1024)
				return mem
			},
		},
	}
}

func (buf *gatewayBufferPool) Get() []byte {
	return buf.pool.Get().([]byte)
}

func (buf *gatewayBufferPool) Put(bs []byte) {
	buf.pool.Put(bs)
}

// Service is a service in a cluster network
type Service struct {
	Name               string             `yaml:"name"`
	URLPath            string             `yaml:"urlPath"`
	Address            string             `yaml:"address"`
	Insecure           bool               `yaml:"insecure"`
	Security           *ServiceTLSOptions `yaml:"security"`
	proxy              *httputil.ReverseProxy
	responseBufferPool httputil.BufferPool
}

// ServiceTLSOptions contains options to configure TLS for a service
type ServiceTLSOptions struct {
	TLSCert    string `yaml:"tlsCert"`
	ServerName string `yaml:"server"`
}

func (srv *Service) init(g *Gateway) error {
	err := srv.validate()
	if err != nil {
		return errors.Wrap(err, "failed to validate service")
	}

	err = srv.createProxy(g)
	if err != nil {
		return errors.Wrap(err, "failed to create service proxy")
	}

	return nil
}

func (srv *Service) validate() error {
	if srv.Address == "" {
		return errors.Errorf("service %q: address cannot be empty", srv.Name)
	}
	if srv.URLPath == "" {
		return errors.Errorf("service %q: url path cannot be empty", srv.Name)
	}

	var (
		warn    bool
		address = strings.TrimPrefix(srv.Address, "https://")
		URLPath = strings.TrimPrefix(srv.URLPath, "/")
	)

	baseScheme := func() string {
		if srv.Insecure {
			return "http"
		}
		return "https"
	}

	scheme := baseScheme()

	address = strings.TrimSuffix(address, "/")
	srv.Address = fmt.Sprintf("%s://%s", scheme, address)

	URLPath = strings.TrimSuffix(URLPath, "/")
	srv.URLPath = fmt.Sprintf("/%s/", URLPath)

	if !srv.Insecure {
		if srv.Security.TLSCert == "" {
			warn = true
			srv.Security.TLSCert = "certs/cert.pem"
			logrus.Warnf("using default tls public key for service %q", srv.Name)
		}
		if srv.Security.ServerName == "" {
			warn = true
			srv.Security.ServerName = "localhost"
			logrus.Warnf("using default tls server name for service %q", srv.Name)
		}
	}

	// Print one line space to separate service warning
	if warn {
		fmt.Println()
	}

	return nil
}

func (srv *Service) createProxy(g *Gateway) error {
	if g == nil {
		return errors.New("service gate should not be nil")
	}
	if srv == nil {
		return errors.Errorf("service %q should not be nil", srv.Name)
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

	// set service proxy client
	srv.proxy = &httputil.ReverseProxy{
		Director:       g.requestMiddleware,
		BufferPool:     newBufferPool(),
		ModifyResponse: g.responseMiddleware,
		ErrorHandler:   g.errorHandler,
		Transport: &http.Transport{
			MaxIdleConns:    50,
			IdleConnTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				ServerName: srv.Security.ServerName,
				RootCAs:    cp,
			},
		},
	}

	return nil
}
