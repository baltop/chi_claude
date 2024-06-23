package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
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

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

func main() {
	r := gin.Default()

	// Middleware
	r.Use(metricsMiddleware())

	// Routes
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome to the API Gateway")
	})

	api := r.Group("/api")
	{
		api.Any("/service-a/*path", gin.WrapH(http.StripPrefix("/api/service-a", proxyHandler(serviceA))))
		api.Any("/service-b/*path", gin.WrapH(http.StripPrefix("/api/service-b", proxyHandler(serviceB))))
	}

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server is running on port %s\n", port)
	log.Fatal(r.Run(":" + port))
}

func proxyHandler(target *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})
}

func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(c.Request.Method, c.Request.URL.Path).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(duration)
	}
}
