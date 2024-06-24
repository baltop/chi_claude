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

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

func main() {
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
		r.With(stripPrefixMiddleware).Get("/service-b/*", proxyHandlerB(serviceB))
		r.With(apiKeyMiddleware).Get("/left", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("left road"))
		})
		r.Mount("/service-a", apiKeyMiddleware(http.StripPrefix("/api/service-a", proxyHandlerA(serviceA))))

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
