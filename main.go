package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// prometheus metrics
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

// Backend service URLs
var (
	serviceA, _ = url.Parse("https://httpbin.org")
	serviceB, _ = url.Parse("https://httpbin.org/")
)

// api key
var apiKeys = []string{
	"e1d9a463-f4c8-4fb6-a92a-ff28f23dc417",
	"06b78225-68e6-46ab-af3b-c981005691cc",
	"a54cbcdd-4054-4364-acd1-717572d491cb",
	"ed0caae6-0b4b-408f-b300-1545e05db00a",
}

func main() {

	plugins := map[string]func(http.Handler) http.Handler{
		"apiKeyMiddleware":      apiKeyMiddleware,
		"stripPrefixMiddleware": stripPrefixMiddleware,
	}

	routerDefinitions := []*RouterDefinition{
		NewRouterDefinition("/api/service-a", "https://httpbin.org", []string{"apiKeyMiddleware"}, nil),
		NewRouterDefinition("/api/service-b", "https://httpbin.org", []string{"stripPrefixMiddleware"}, nil),
		NewRouterDefinition("/api/service-c", "https://httpbin.org", nil, nil), // no middleware
	}

	for _, r := range routerDefinitions {
		for _, mwname := range r.mwname {
			if mw, ok := plugins[mwname]; ok {
				r.addMiddleware(mw)
			}
		}
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(metricsMiddleware)

	// Routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to the API Gateway"))
	})

	r.Route("/api", func(r chi.Router) {

		for _, def := range routerDefinitions {
			url, _ := url.Parse(def.Upstream)
			// method가 * 이면?   r.With(def.middleware...).HandleFunc(def.ListenPath, proxyHandlerB(url))
			r.With(def.middleware...).Method(def.Method, def.ListenPath, proxyHandlerB(url))
		}

		// routerDefinitions를 이용한 위 코드면 완성.  아래는 그냥 참고용 샘플 코드.
		r.With(stripPrefixMiddleware).Get("/service-b/*", proxyHandlerB(serviceB))

		r.With(apiKeyMiddleware).Get("/left/*", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("left road"))
		})

		// url이 긴거 부터 먼저 매칭됨
		r.With(apiKeyMiddleware).Get("/left/east/*", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("left east road"))
		})

		// mount 방식은 새로운 라우터를 만드는데, 모든 메소드를 컨트롤
		r.Mount("/service-a", apiKeyMiddleware(http.StripPrefix("/api/service-a", proxyHandlerA(serviceA))))
		r.With(apiKeyMiddleware).Mount("/service-c", http.StripPrefix("/api/service-c", proxyHandlerA(serviceA)))
	})

	r.Handle("/metrics", promhttp.Handler())

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server is running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func proxyHandlerA(target *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})
}

func proxyHandlerB(target *url.URL) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		for _, key := range apiKeys {
			if apiKey == key {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func stripPrefixMiddleware(next http.Handler) http.Handler {
	prefix := "/api/service-b"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := strings.TrimPrefix(r.URL.Path, prefix); len(p) < len(r.URL.Path) {
			r.URL.Path = p
			next.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}

type RouterDefinition struct {
	ListenPath string
	Method     string
	Upstream   string
	mwname     []string
	middleware []func(http.Handler) http.Handler
}

func NewRouterDefinition(listenPath, method, upstream string, mwname []string, middleware ...func(http.Handler) http.Handler) *RouterDefinition {
	return &RouterDefinition{
		ListenPath: listenPath,
		Method:     method,
		Upstream:   upstream,
		middleware: middleware,
	}
}

func (r *RouterDefinition) addMiddleware(middleware func(http.Handler) http.Handler) {
	r.middleware = append(r.middleware, middleware)
}
