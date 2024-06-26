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

// main 함수
func main() {

	// 미들웨어 플러그인의 설정값을 읽어서 map에 저장
	plugins := map[string]func(http.Handler) http.Handler{
		"apiKeyMiddleware":      apiKeyMiddleware,
		"stripPrefixMiddleware": stripPrefixMiddleware,
	}

	// reouterDefinition을 설정파일이나 DB에서 읽어와서 저장
	routerDefinitions := []*RouterDefinition{
		NewRouterDefinition("/api/service-a", "GET", "https://httpbin.org", []string{"apiKeyMiddleware"}, nil),
		NewRouterDefinition("/api/service-b", "POST", "https://httpbin.org", []string{"stripPrefixMiddleware"}, nil),
		NewRouterDefinition("/api/service-c", "*", "https://httpbin.org", nil, nil), // no middleware
	}

	// 스트링으로 된 설정값의 미들웨어 명을 실제 미들웨어 함수의 슬라이스로 변환하여 routerDefinition에 저장
	for _, r := range routerDefinitions {
		for _, mwname := range r.mwname {
			if mw, ok := plugins[mwname]; ok {
				r.addMiddleware(mw)
			}
		}
	}

	// default root router
	r := chi.NewRouter()

	// 전역으로 사용될 Middleware. api 라우터 별로 설정되는 미들웨어는 플러그인이라고 부르고 routerDefinition에 따라 개별 저장
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(metricsMiddleware)

	// 디폴트 테스트 Routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to the API Gateway"))
	})

	// /api의 서브 라우터 설정
	r.Route("/api", func(r chi.Router) {

		for _, def := range routerDefinitions {
			url, _ := url.Parse(def.Upstream)
			// method가 * 이면?   r.With(def.middleware...).HandleFunc(def.ListenPath, proxyHandlerB(url))
			if def.Method == "*" {
				r.With(def.middleware...).HandleFunc(def.ListenPath, proxyHandlerB(url))
				continue
			}
			r.With(def.middleware...).Method(def.Method, def.ListenPath, proxyHandlerB(url))
		}

		//
		// routerDefinitions를 이용한 위 코드면 완성.  아래는 그냥 참고용 샘플 코드.
		//
		r.With(stripPrefixMiddleware).Get("/service-b/*", proxyHandlerB(serviceB))

		// 아래와 비교
		r.With(apiKeyMiddleware).Get("/left/*", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("left road"))
		})

		// url이 긴거 부터 먼저 매칭됨
		r.With(apiKeyMiddleware).Get("/left/east/*", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("left east road"))
		})

		// mount 방식은 새로운 라우터를 만드는데, 메소드를 붙일 수 없이 전부 다 적용되고 listenPath에 * 없는데 주의할 것.
		r.Mount("/service-a", apiKeyMiddleware(http.StripPrefix("/api/service-a", proxyHandlerA(serviceA))))
		r.With(apiKeyMiddleware).Mount("/service-c", http.StripPrefix("/api/service-c", proxyHandlerA(serviceA)))
	})

	// Prometheus metrics handler 프로메테우스 서버에서 데이터 수집할때 접근하는 url
	r.Handle("/metrics", promhttp.Handler())

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server is running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))

}

// retrun http.Handler  interface
func proxyHandlerA(target *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})
}

// return http.HandlerFunc  type
func proxyHandlerB(target *url.URL) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})
}

// prometheus 메트릭스를 수집하기 위한 middleware
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

// apikey를 체크하기 위한 미들웨어
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

// upstream으로 보내기 전에 url에서 prefix를 제거하기 위한 미들웨어
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
