package gateway

import (
	"fmt"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
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

// serviceGate contains information about gateway services and internals
type serviceGate struct {
	muxer              *http.ServeMux
	requestMiddleware  func(*http.Request)
	responseMiddleware func(*http.Response) error
	errorHandler       func(http.ResponseWriter, *http.Request, error)
	services           map[string]*Service
	servicesFile       string
	redirectStatus     int
	development        bool
}

// New creates a service gateway that proxies requests to the most appropriate service in the services entries.
func New(redirectCode int, services []*Service) (h http.Handler, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("unrecoverable error happened: %v", err1)
		}
	}()

	gw := &serviceGate{
		muxer:              http.NewServeMux(),
		services:           make(map[string]*Service),
		redirectStatus:     redirectCode,
		requestMiddleware:  func(*http.Request) {},
		responseMiddleware: func(*http.Response) error { return nil },
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
			Security:    &ServiceTLSOptions{},
			HTTP2: &HTTP2Options{
				ServerPush: &ServerPush{},
			},
		}
		gwServices[srv.Name].Security.TLSCert = srv.Security.TLSCert
		gwServices[srv.Name].Security.TLSKey = srv.Security.TLSKey
		gwServices[srv.Name].Security.ServerName = srv.Security.ServerName
	}

	gw.services = gwServices

	err = gw.updateServices()
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, nil
}

// NewFromFile creates a service gateway that provies requests to the most appropriate service by reading services configuration from yaml file
func NewFromFile(redirectCode int, servicesFile string) (h http.Handler, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("panic happened: %v", err1)
		}
	}()

	gw := &serviceGate{
		muxer:              http.NewServeMux(),
		services:           make(map[string]*Service),
		servicesFile:       servicesFile,
		redirectStatus:     redirectCode,
		requestMiddleware:  func(*http.Request) {},
		responseMiddleware: func(*http.Response) error { return nil },
	}

	// Set mode for handling CORS
	mode, ok := os.LookupEnv("MODE")
	if ok {
		mode, err := strconv.ParseBool(mode)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read mode")
		}
		gw.development = mode
	}

	// Read the service definitions from YAML
	services, err := readYAML(servicesFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read read YAML")
	}

	gw.services = services

	err = gw.updateServices()
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, err
}

func (serviceGate *serviceGate) updateServices() error {
	for serviceID, srv := range serviceGate.services {
		// its safe
		if srv.HTTP2 == nil {
			srv.HTTP2 = &HTTP2Options{
				ServerPush: &ServerPush{
					Enabled: false,
				},
			}
		}

		// its more safe
		if srv.HTTP2.ServerPush == nil {
			srv.HTTP2.ServerPush = &ServerPush{
				Enabled: false,
			}
		}

		srv.Name = serviceID

		err := srv.init(serviceGate)
		if err != nil {
			return errors.Errorf("failed to update service %q: %v", serviceID, err)
		}

		serviceID := serviceID
		path := strings.TrimSuffix(srv.GatewayPath, "/") + "/"

		// update muxer for the service
		serviceGate.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			serviceGate.proxy(w, r, serviceID)
		})
	}

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

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func (serviceGate *serviceGate) proxy(w http.ResponseWriter, r *http.Request, serviceID string) {
	srv, ok := serviceGate.services[serviceID]
	if !ok {
		http.Error(w, fmt.Sprintf("service %q not found", serviceID), http.StatusNotFound)
		return
	}

	// push content to the client if the service has push support
	srv.pushContent(w, r)

	newURL, err := url.Parse(srv.Address + r.URL.Path)
	if err != nil && err != io.EOF {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// update the URL paths
	r.Host = newURL.Host
	r.URL.Host = newURL.Host
	r.URL.Scheme = newURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))

	// update CORs headers
	if serviceGate.development {
		w.Header().Set("access-control-allow-origin", r.Header.Get("origin"))
		w.Header().Set("access-control-allow-credentials", "true")
	}

	srv.proxy.ServeHTTP(w, r)
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

	err = yaml.UnmarshalStrict(bs, srvs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal yaml")
	}

	return srvs.Services, nil
}
