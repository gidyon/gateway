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
	"path/filepath"
	"strings"
	"time"
)

// Service is a service in a cluster network
type Service struct {
	Name               string             `yaml:"name"`
	GatewayPath        string             `yaml:"gatewayPath"`
	Address            string             `yaml:"address"`
	Port               int                `yaml:"port"`
	Security           *ServiceTLSOptions `yaml:"security"`
	HTTP2              *HTTP2Options      `yaml:"http2"`
	proxy              *httputil.ReverseProxy
	responseBufferPool httputil.BufferPool
}

// ServiceTLSOptions contains options to configure TLS for a service
type ServiceTLSOptions struct {
	TLSKey     string `yaml:"tlsKey"`
	TLSCert    string `yaml:"tlsCert"`
	ServerName string `yaml:"server"`
}

// HTTP2Options contains options to be used to set http2 functionalities
type HTTP2Options struct {
	ServerPush *ServerPush `yaml:"serverPush"`
}

// ServerPush contains options for http2 Server Push
type ServerPush struct {
	Enabled      bool                `yaml:"enabled"`
	PushContents []*PushContent      `yaml:"pushContents"`
	pushMap      map[string][]string `yaml:"-"`
	options      *http.PushOptions   `yaml:"-"`
}

// PushContent contains content to push to client when any of paths is accessed
type PushContent struct {
	Paths       []string `yaml:"paths"`
	Directories []string `yaml:"dirs"`
	Files       []string `yaml:"files"`
}

func (srv *Service) init(serviceGate *serviceGate) error {
	err := srv.validate()
	if err != nil {
		return errors.Wrap(err, "failed to validate service")
	}

	err = srv.createProxy(serviceGate)
	if err != nil {
		return errors.Wrap(err, "failed to create service proxy")
	}

	err = srv.updateHTTP2(serviceGate)
	if err != nil {
		return errors.Wrap(err, "failed to updated service http2 features")
	}

	return nil
}

func (srv *Service) validate() error {
	var (
		warn        bool
		address     = strings.TrimPrefix(srv.Address, "https://")
		gatewayPath = strings.TrimPrefix(srv.GatewayPath, "/")
	)

	address = strings.TrimSuffix(address, "/")
	srv.Address = fmt.Sprintf("https://%s", address)
	if srv.Address == "" {
		return errors.Errorf("service %q: address cannot be empty", srv.Name)
	}

	srv.GatewayPath = fmt.Sprintf("/%s", gatewayPath)
	if srv.GatewayPath == "" {
		return errors.Errorf("service %q: gateway path cannot be empty", srv.Name)
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

func (srv *Service) createProxy(serviceGate *serviceGate) error {
	if serviceGate == nil {
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
		Director:       serviceGate.requestMiddleware,
		BufferPool:     newBufferPool(),
		ModifyResponse: serviceGate.responseMiddleware,
		ErrorHandler:   serviceGate.errorHandler,
		Transport: &http.Transport{
			MaxIdleConns:    50,
			IdleConnTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				ServerName:         srv.Security.ServerName,
				RootCAs:            cp,
				InsecureSkipVerify: true,
			},
		},
	}

	return nil
}

func (srv *Service) updateHTTP2(serviceGate *serviceGate) error {
	if srv.HTTP2 == nil {
		return nil
	}

	// add server push
	err := srv.addServerPush()
	if err != nil {
		return err
	}

	return nil
}

func (srv *Service) addServerPush() error {
	serverPush := srv.HTTP2.ServerPush
	if serverPush != nil {
		serverPush.options = &http.PushOptions{
			Method: http.MethodGet,
			Header: http.Header{
				"pushed-from": []string{"api"},
			},
		}
		serverPush.pushMap = make(map[string][]string, 0)
		serverPushFiles := serverPush.pushMap

		// Enable push support for this service
		if serverPush.PushContents != nil && len(serverPush.PushContents) > 0 {
			serverPush.Enabled = true
		}

		for _, pushContent := range serverPush.PushContents {
			for _, pushPath := range pushContent.Paths {
				// path to have / at beginning
				path := "/" + strings.TrimPrefix(pushPath, "/")

				// add files
				for _, file := range pushContent.Files {
					target := "/" + strings.TrimPrefix(file, "/")
					serverPushFiles[path] = append(serverPushFiles[path], target)
				}

				// add directories
				for _, dir := range pushContent.Directories {
					fileInfos, err := ioutil.ReadDir(dir)
					if err != nil {
						return errors.Wrap(err, "failed to read directory files")
					}

					// add directory files
					for _, fileInfo := range fileInfos {
						target := "/" + strings.TrimPrefix(
							filepath.Join(dir, fileInfo.Name()), "/",
						)
						serverPushFiles[path] = append(serverPushFiles[path], target)
					}
				}
			}
		}
	}

	return nil
}

func (srv *Service) pushContent(w http.ResponseWriter, r *http.Request) {
	// push content to the client if the service has push support
	if srv.HTTP2.ServerPush.Enabled {
		// check if url path is in list of server push paths
		pushFiles, ok := srv.HTTP2.ServerPush.pushMap[r.URL.Path]
		if ok {
			pusher, ok := w.(http.Pusher)
			if ok {
				for _, target := range pushFiles {
					// push content
					pusher.Push(target, srv.HTTP2.ServerPush.options)
				}
			}
		}
	}
}
