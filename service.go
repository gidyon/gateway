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

// newBufferPool creates a bytes pool to be used by reverse proxy server while copying responses
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
	Port               int                `yaml:"port"`
	Security           *ServiceTLSOptions `yaml:"security"`
	proxy              *httputil.ReverseProxy
	responseBufferPool httputil.BufferPool
}

// ServiceTLSOptions contains options to configure TLS for a service
type ServiceTLSOptions struct {
	TLSKey     string `yaml:"tlsKey"`
	TLSCert    string `yaml:"tlsCert"`
	ServerName string `yaml:"server"`
}

func (srv *Service) update(serviceGate *ServiceGate) error {
	// checks service information is correct
	err := srv.validate()
	if err != nil {
		return errors.Wrap(err, "failed to validate service")
	}

	// creates a proxy for the service
	err = srv.createProxy(serviceGate)
	if err != nil {
		return errors.Wrap(err, "failed to create service proxy")
	}

	return nil
}

func (srv *Service) validate() error {
	var (
		warn bool
	)

	address := strings.TrimPrefix(strings.TrimSuffix(srv.Address, "/"), "https://")
	srv.Address = fmt.Sprintf("https://%s", address)
	if srv.Address == "" {
		return errors.Errorf("service %q address cannot be empty", srv.Name)
	}

	URLPath := strings.TrimPrefix(srv.URLPath, "/")
	srv.URLPath = fmt.Sprintf("/%s", URLPath)
	if srv.URLPath == "" {
		return errors.Errorf("service %q url path cannot be empty", srv.Name)
	}

	if srv.Port == 0 {
		warn = true
		srv.Port = 443
		logrus.Warnf("using default port 443 for service %q", srv.Name)
	}

	if srv.Security.TLSCert == "" {
		warn = true
		srv.Security.TLSCert = "certs/cert.pem"
		logrus.Warnf("using default tls public key for service %q", srv.Name)
	}
	if srv.Security.ServerName == "" {
		warn = true
		logrus.Warnf("using default tls server name for service %q", srv.Name)
	}

	// Print one line space to separate service warning
	if warn {
		fmt.Println()
	}

	return nil
}

func (srv *Service) createProxy(serviceGate *ServiceGate) error {
	if serviceGate == nil {
		return errors.New("service gateway should not be nil")
	}
	if srv == nil {
		return errors.Errorf("service %q should not be nil", srv.Name)
	}

	b, err := ioutil.ReadFile(srv.Security.TLSCert)
	if err != nil {
		return errors.Wrap(err, "failed to read cert file")
	}

	// append to cert pool
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		msg := fmt.Sprintf("failed to append cert file: %v", err)
		return errors.New(msg)
	}

	// set service proxy client
	srv.proxy = &httputil.ReverseProxy{
		Director:       serviceGate.requestMiddleware,
		BufferPool:     newBufferPool(),
		ModifyResponse: serviceGate.responseMiddleware,
		ErrorHandler:   serviceGate.errorHandler,
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
