package gateway

import (
	"fmt"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// ServiceGate hold internals of gateway services
type ServiceGate struct {
	muxer              *http.ServeMux
	middlewares        []func(http.Handler) http.Handler
	requestMiddleware  func(*http.Request)
	responseMiddleware func(*http.Response) error
	errorHandler       func(http.ResponseWriter, *http.Request, error)
	services           map[string]*Service
	servicesFile       string
}

func newServiceGate() *ServiceGate {
	gw := &ServiceGate{
		muxer:              http.NewServeMux(),
		middlewares:        make([]func(http.Handler) http.Handler, 0),
		services:           make(map[string]*Service),
		requestMiddleware:  func(*http.Request) {},
		responseMiddleware: func(*http.Response) error { return nil },
	}

	return gw
}

// New creates a service gateway from the services map provided
func New(services map[string]*Service) (gw *ServiceGate, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("unrecoverable error happened: %v", err1)
		}
	}()

	err = gw.registerServices(services)
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, nil
}

// NewFromFile creates a service gateway from a yaml services definition file
func NewFromFile(redirectCode int, servicesFile string) (gw *ServiceGate, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("panic happened: %v", err1)
		}
	}()

	gw = newServiceGate()

	// Read the service definitions from YAML
	services, err := readYAML(servicesFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read read YAML")
	}

	err = gw.registerServices(services)
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, err
}

// AddMiddlewares adds middlewares to the gateway
func (gateway *ServiceGate) AddMiddlewares(middlewares ...func(http.Handler) http.Handler) {
	gateway.middlewares = append(gateway.middlewares, middlewares...)
}

// Handle registers a handler to the gateweay at provided path
func (gateway *ServiceGate) Handle(path string, handler http.Handler) {
	if gateway.muxer == nil {
		gateway.muxer = http.NewServeMux()
	}
	gateway.muxer.Handle(path, handler)
}

// HandleFunc registers a handler to the gateway at provided path
func (gateway *ServiceGate) HandleFunc(path string, handler http.HandlerFunc) {
	if gateway.muxer == nil {
		gateway.muxer = http.NewServeMux()
	}
	gateway.muxer.HandleFunc(path, handler)
}

// Handler returns the http handler for the gateway
func (gateway *ServiceGate) Handler() http.Handler {
	// Apply middlewares
	apply := func(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
		if len(middlewares) < 1 {
			return handler
		}
		wrapped := handler
		for i := len(middlewares) - 1; i >= 0; i-- {
			wrapped = middlewares[i](wrapped)
		}
		return wrapped
	}

	return apply(gateway.muxer, gateway.middlewares...)
}

// proxies request to the appropriate service
func (gateway *ServiceGate) proxy(w http.ResponseWriter, r *http.Request, serviceID string) {
	srv, ok := gateway.services[serviceID]
	if !ok {
		http.Error(w, fmt.Sprintf("service %q not found", serviceID), http.StatusNotFound)
		return
	}

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

	srv.proxy.ServeHTTP(w, r)
}

// update and register services to gateway
func (gateway *ServiceGate) registerServices(services map[string]*Service) error {
	var err error
	for serviceID, srv := range services {
		serviceID := serviceID
		srv.Name = serviceID

		err = srv.update(gateway)
		if err != nil {
			return errors.Errorf("failed to update service %q: %v", serviceID, err)
		}

		path := strings.TrimSuffix(srv.URLPath, "/") + "/"

		// update muxer for the service
		gateway.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			gateway.proxy(w, r, serviceID)
		})
	}

	return nil
}

// reads and parses yaml from file
func readYAML(filename string) (map[string]*Service, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read from file")
	}

	// Services definition structure
	type services struct {
		Services map[string]*Service
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
