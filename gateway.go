package gateway

import (
	"fmt"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Gateway contains information about gateway services and internals
type Gateway struct {
	muxer              *http.ServeMux
	middlewares        []func(http.Handler) http.Handler
	requestMiddleware  func(*http.Request)
	responseMiddleware func(*http.Response) error
	errorHandler       func(http.ResponseWriter, *http.Request, error)
	services           map[string]*Service
	servicesFile       string
}

func newGateway(services map[string]*Service) *Gateway {
	gw := &Gateway{
		muxer:              http.NewServeMux(),
		requestMiddleware:  func(*http.Request) {},
		responseMiddleware: func(*http.Response) error { return nil },
		services:           services,
	}
	return gw
}

// New creates a service gateway that proxies requests to the most appropriate service in the services entries.
func New(services map[string]*Service) (gw *Gateway, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("unrecoverable error happened: %v", err1)
		}
	}()

	gw = newGateway(services)

	err = gw.updateServices()
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, nil
}

// NewFromFile creates a service gateway that provies requests to the most appropriate service by reading services configuration from yaml file
func NewFromFile(servicesFile string) (gw *Gateway, err error) {
	defer func() {
		if err1 := recover(); err1 != nil {
			err = errors.Errorf("panic happened: %v", err1)
		}
	}()

	// Read the service definitions from YAML
	services, err := readYAML(servicesFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read read YAML")
	}

	gw = newGateway(services)

	err = gw.updateServices()
	if err != nil {
		return nil, errors.Wrap(err, "failed to update gateway")
	}

	return gw, err
}

// AddMiddlewares registers the handler for the given pattern.
func (g *Gateway) AddMiddlewares(middleware func(http.Handler) http.Handler) {
	if g.middlewares == nil {
		g.middlewares = make([]func(http.Handler) http.Handler, 0)
	}
	g.middlewares = append(g.middlewares, middleware)
}

// Handle registers the handler for the given pattern.
func (g *Gateway) Handle(pattern string, handler http.Handler) {
	g.muxer.Handle(pattern, handler)
}

// HandleFunc registers the handler function for the given pattern.
func (g *Gateway) HandleFunc(pattern string, handler func(w http.ResponseWriter, r *http.Request)) {
	g.muxer.HandleFunc(pattern, handler)
}

// Handler returns http.Handler for the gateway
func (g *Gateway) Handler() http.Handler {
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

	return apply(g.muxer, g.middlewares...)
}

func (g *Gateway) updateServices() error {
	for serviceID, srv := range g.services {
		serviceID := serviceID
		srv.Name = serviceID

		err := srv.init(g)
		if err != nil {
			return errors.Errorf("failed to initialize service %q: %v", serviceID, err)
		}

		// update muxer for the service
		g.muxer.HandleFunc(srv.URLPath, func(w http.ResponseWriter, r *http.Request) {
			g.proxy(w, r, serviceID)
		})
	}

	return nil
}

func (g *Gateway) proxy(w http.ResponseWriter, r *http.Request, serviceID string) {
	srv, ok := g.services[serviceID]
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

// reads and parses yaml from file
func readYAML(filename string) (map[string]*Service, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read from file")
	}

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
