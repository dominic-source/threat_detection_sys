package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	routers "github.com/getkin/kin-openapi/routers"
	gorillamux "github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var (
	rdb    *redis.Client
	router routers.Router
	proxy  *httputil.ReverseProxy

	userHashSecret []byte
	jwtSecret      []byte

	// Telemetry queue.
	telemetryCh chan TelemetryEvent
)

// Configuration.
const (
	serverAddr         = ":8080"
	openAPIPath        = "/etc/gateway/openapi.yaml"
	telemetryStream    = "stream:telemetry"
	telemetryQueueSize = 10000

	// Maximum request body size.
	maxRequestBodySize = 10 << 20 // 10 MiB

	// Rate limit.
	rateLimitRequests = 100
	rateLimitWindow   = time.Minute
)

// TelemetryEvent represents one API request/response event.
type TelemetryEvent struct {
	EventType      string
	Route          string
	UserHash       string
	URI            string
	Method         string
	IP             string
	PayloadSize    int64
	Timestamp      int64
	StatusCode     int
	RequestID      string
	UserAgentHash  string
	LatencyMicros  int64
	RateLimitState string
	TLSInformation string
	ResponseSize   int64
}

// responseRecorder records response metadata while still behaving
// like a normal http.ResponseWriter.
type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
}

func (rw *responseRecorder) WriteHeader(statusCode int) {
	if rw.wroteHeader {
		return
	}

	rw.statusCode = statusCode
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseRecorder) Write(data []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}

	n, err := rw.ResponseWriter.Write(data)
	atomic.AddInt64(&rw.bytesWritten, int64(n))

	return n, err
}

func (rw *responseRecorder) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		if !rw.wroteHeader {
			rw.WriteHeader(http.StatusOK)
		}

		flusher.Flush()
	}
}

func (rw *responseRecorder) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func main() {
	// 1. Load configuration

	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")

	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		log.Fatal("BACKEND_URL is required")
	}

	parsedBackendURL, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("invalid BACKEND_URL: %v", err)
	}

	userHashSecretString := os.Getenv("USER_HASH_SECRET")
	if userHashSecretString == "" {
		log.Fatal("USER_HASH_SECRET is required")
	}

	jwtSecretString := os.Getenv("JWT_SECRET")
	if jwtSecretString == "" {
		log.Fatal("JWT_SECRET is required")
	}

	userHashSecret = []byte(userHashSecretString)
	jwtSecret = []byte(jwtSecretString)

	// 2. Connect to Redis
	rdb = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	log.Println("Redis connection successful")

	// 3. Load and validate OpenAPI specification
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromFile(openAPIPath)
	if err != nil {
		log.Fatalf("failed to load OpenAPI spec: %v", err)
	}

	if err := doc.Validate(context.Background()); err != nil {
		log.Fatalf("OpenAPI specification is invalid: %v", err)
	}

	r, err := gorillamux.NewRouter(doc)
	if err != nil {
		log.Fatalf("failed to create OpenAPI router: %v", err)
	}

	router = r

	log.Println("OpenAPI specification loaded and validated")

	// 4. Create reverse proxy
	proxy = httputil.NewSingleHostReverseProxy(parsedBackendURL)

	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		// Preserve the request ID.
		if requestID := pr.In.Header.Get("X-Request-ID"); requestID != "" {
			pr.Out.Header.Set("X-Request-ID", requestID)
		}

		// Tell the backend that this request came through the gateway.
		pr.Out.Header.Set("X-Gateway", "api-gateway")

		// Set X-Forwarded-For, X-Forwarded-Host and X-Forwarded-Proto.
		pr.SetXForwarded()
	}

	proxy.ErrorHandler = func(
		w http.ResponseWriter,
		r *http.Request,
		err error,
	) {
		log.Printf(
			"backend proxy error request_id=%s error=%v",
			r.Header.Get("X-Request-ID"),
			err,
		)

		http.Error(
			w,
			"backend unavailable",
			http.StatusBadGateway,
		)
	}
	// 5. Start telemetry queue

	telemetryCh = make(chan TelemetryEvent, telemetryQueueSize)

	// Start ONE worker.
	go telemetryWorker()

	// 6. Start HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", gatewayHandler)

	srv := &http.Server{
		Addr:              serverAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("gateway listening on %s", serverAddr)
	log.Printf("backend: %s", parsedBackendURL)
	log.Fatal(srv.ListenAndServe())
}

// The main security gateway pipeline.
func gatewayHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Use the request's context.
	ctx := r.Context()

	// 1. Request ID

	requestID := uuid.NewString()

	r.Header.Set("X-Request-ID", requestID)

	// 2. Wrap response writer so we can capture response metadata.
	recorder := &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// 3. Extract client IP
	ip := clientIP(r)

	// 4. Prevent excessively large request bodies.
	r.Body = http.MaxBytesReader(
		recorder,
		r.Body,
		maxRequestBodySize,
	)

	// 5. Read request body.
	//
	// We need this because OpenAPI validation may need to read it.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(
			recorder,
			"request body too large or unreadable",
			http.StatusRequestEntityTooLarge,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:   "request_rejected",
			URI:         r.URL.Path,
			Method:      r.Method,
			IP:          ip,
			PayloadSize: int64(len(body)),
			Timestamp:   time.Now().UnixMicro(),
			StatusCode:  recorder.statusCode,
			RequestID:   requestID,
			UserAgentHash: hashUserAgent(
				r.UserAgent(),
			),
			LatencyMicros: time.Since(start).Microseconds(),
		})

		return
	}

	// Restore body for OpenAPI validator and reverse proxy.
	r.Body = io.NopCloser(bytes.NewReader(body))

	payloadSize := int64(len(body))

	// 6. Authenticate request.
	userID, err := authenticateRequest(r)
	if err != nil {
		http.Error(
			recorder,
			"unauthorized",
			http.StatusUnauthorized,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:      "authentication_failed",
			URI:            r.URL.Path,
			Method:         r.Method,
			IP:             ip,
			PayloadSize:    payloadSize,
			Timestamp:      time.Now().UnixMicro(),
			StatusCode:     recorder.statusCode,
			RequestID:      requestID,
			UserAgentHash:  hashUserAgent(r.UserAgent()),
			LatencyMicros:  time.Since(start).Microseconds(),
			RateLimitState: "not_checked",
		})

		return
	}

	// 7. HMAC pseudonymisation of authenticated user ID.
	userHash := hashUserID(userID, userHashSecret)

	// 8. Check blocklist.
	blockKey := fmt.Sprintf(
		"blocklist:%s",
		userHash,
	)

	exists, err := rdb.Exists(ctx, blockKey).Result()
	if err != nil {
		http.Error(
			recorder,
			"security service unavailable",
			http.StatusServiceUnavailable,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:     "security_check_failed",
			UserHash:      userHash,
			URI:           r.URL.Path,
			Method:        r.Method,
			IP:            ip,
			PayloadSize:   payloadSize,
			Timestamp:     time.Now().UnixMicro(),
			StatusCode:    recorder.statusCode,
			RequestID:     requestID,
			UserAgentHash: hashUserAgent(r.UserAgent()),
			LatencyMicros: time.Since(start).Microseconds(),
		})

		return
	}

	if exists > 0 {
		http.Error(
			recorder,
			"blocked",
			http.StatusForbidden,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:      "blocked_user",
			UserHash:       userHash,
			URI:            r.URL.Path,
			Method:         r.Method,
			IP:             ip,
			PayloadSize:    payloadSize,
			Timestamp:      time.Now().UnixMicro(),
			StatusCode:     recorder.statusCode,
			RequestID:      requestID,
			UserAgentHash:  hashUserAgent(r.UserAgent()),
			LatencyMicros:  time.Since(start).Microseconds(),
			RateLimitState: "not_checked",
		})

		return
	}

	// 9. IP-based rate limiting.
	rateLimitKey := fmt.Sprintf(
		"ratelimit:ip:%s",
		ip,
	)

	allowed, err := rateLimit(
		ctx,
		rateLimitKey,
		rateLimitRequests,
		rateLimitWindow,
	)

	if err != nil {
		http.Error(
			recorder,
			"rate limiter unavailable",
			http.StatusServiceUnavailable,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:      "rate_limit_error",
			UserHash:       userHash,
			URI:            r.URL.Path,
			Method:         r.Method,
			IP:             ip,
			PayloadSize:    payloadSize,
			Timestamp:      time.Now().UnixMicro(),
			StatusCode:     recorder.statusCode,
			RequestID:      requestID,
			UserAgentHash:  hashUserAgent(r.UserAgent()),
			LatencyMicros:  time.Since(start).Microseconds(),
			RateLimitState: "error",
		})

		return
	}

	rateLimitState := "allowed"

	if !allowed {
		rateLimitState = "blocked"

		http.Error(
			recorder,
			"rate limit exceeded",
			http.StatusTooManyRequests,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:      "rate_limited",
			UserHash:       userHash,
			URI:            r.URL.Path,
			Method:         r.Method,
			IP:             ip,
			PayloadSize:    payloadSize,
			Timestamp:      time.Now().UnixMicro(),
			StatusCode:     recorder.statusCode,
			RequestID:      requestID,
			UserAgentHash:  hashUserAgent(r.UserAgent()),
			LatencyMicros:  time.Since(start).Microseconds(),
			RateLimitState: rateLimitState,
		})

		return
	}

	// 10. OpenAPI route matching.
	route, pathParams, err := router.FindRoute(r)

	if err != nil {
		// kin-openapi distinguishes path-not-found and
		// method-not-allowed route errors.
		status := http.StatusNotFound

		if errors.Is(err, routers.ErrMethodNotAllowed) {
			status = http.StatusMethodNotAllowed
		}

		http.Error(
			recorder,
			"route not found",
			status,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:      "route_rejected",
			UserHash:       userHash,
			URI:            r.URL.Path,
			Method:         r.Method,
			IP:             ip,
			PayloadSize:    payloadSize,
			Timestamp:      time.Now().UnixMicro(),
			StatusCode:     recorder.statusCode,
			RequestID:      requestID,
			UserAgentHash:  hashUserAgent(r.UserAgent()),
			LatencyMicros:  time.Since(start).Microseconds(),
			RateLimitState: rateLimitState,
		})

		return
	}

	if route == nil {
		http.Error(
			recorder,
			"route not found",
			http.StatusNotFound,
		)

		return
	}

	// 11. OpenAPI request validation.
	input := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			MultiError: true,
		},
	}

	if err := openapi3filter.ValidateRequest(ctx, input); err != nil {
		http.Error(
			recorder,
			"schema validation failed",
			http.StatusBadRequest,
		)

		enqueueTelemetry(TelemetryEvent{
			EventType:      "schema_validation_failed",
			UserHash:       userHash,
			Route:          route.Path,
			URI:            r.URL.Path,
			Method:         r.Method,
			IP:             ip,
			PayloadSize:    payloadSize,
			Timestamp:      time.Now().UnixMicro(),
			StatusCode:     recorder.statusCode,
			RequestID:      requestID,
			UserAgentHash:  hashUserAgent(r.UserAgent()),
			LatencyMicros:  time.Since(start).Microseconds(),
			RateLimitState: rateLimitState,
		})

		return
	}

	// 12. Determine route.
	routePath := route.Path

	// 13. Proxy request to backend.
	proxy.ServeHTTP(recorder, r)

	// 14. Calculate final request metrics.
	elapsed := time.Since(start)

	responseSize := atomic.LoadInt64(
		&recorder.bytesWritten,
	)

	// 15. Queue telemetry.
	enqueueTelemetry(TelemetryEvent{
		EventType:      "api_request",
		UserHash:       userHash,
		Route:          routePath,
		URI:            r.URL.Path,
		Method:         r.Method,
		IP:             ip,
		PayloadSize:    payloadSize,
		Timestamp:      time.Now().UnixMicro(),
		StatusCode:     recorder.statusCode,
		RequestID:      requestID,
		UserAgentHash:  hashUserAgent(r.UserAgent()),
		LatencyMicros:  elapsed.Microseconds(),
		RateLimitState: rateLimitState,
		TLSInformation: tlsInformation(r),
		ResponseSize:   responseSize,
	})

	// 16. Gateway logging.

	log.Printf(
		"served request_id=%s method=%s uri=%s route=%s user=%s ip=%s status=%d payload=%d response=%d latency=%s",
		requestID,
		r.Method,
		r.URL.Path,
		routePath,
		shortHash(userHash),
		ip,
		recorder.statusCode,
		payloadSize,
		responseSize,
		elapsed,
	)
}

// authenticateRequest verifies the JWT in:
//
// Authorization: Bearer <token>
//
// This implementation expects HS256 JWTs.
func authenticateRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Fields(authHeader)

	if len(parts) != 2 ||
		!strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization header")
	}

	tokenString := parts[1]

	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{
			jwt.SigningMethodHS256.Alg(),
		}),
		jwt.WithExpirationRequired(),
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer != "" {
		options = append(
			options,
			jwt.WithIssuer(issuer),
		)
	}

	audience := os.Getenv("JWT_AUDIENCE")
	if audience != "" {
		options = append(
			options,
			jwt.WithAudience(audience),
		)
	}

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf(
					"unexpected signing method: %s",
					token.Method.Alg(),
				)
			}

			return jwtSecret, nil
		},
		options...,
	)

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return "", errors.New("missing subject claim")
	}

	return subject, nil
}

// hashUserID creates a keyed HMAC-SHA256 pseudonym.
func hashUserID(userID string, secret []byte) string {
	mac := hmac.New(
		sha256.New,
		secret,
	)

	_, _ = mac.Write([]byte(userID))

	return hex.EncodeToString(
		mac.Sum(nil),
	)
}

// hashUserAgent avoids storing the raw user-agent in telemetry.
func hashUserAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}

	return hashUserID(
		userAgent,
		userHashSecret,
	)
}

// rateLimit implements a simple fixed-window Redis rate limiter.
func rateLimit(
	ctx context.Context,
	key string,
	limit int,
	window time.Duration,
) (bool, error) {

	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	if count == 1 {
		if err := rdb.Expire(
			ctx,
			key,
			window,
		).Err(); err != nil {
			return false, err
		}
	}

	return count <= int64(limit), nil
}

// clientIP extracts the directly connected peer IP.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(
		r.RemoteAddr,
	)

	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// tlsInformation records basic TLS metadata.
func tlsInformation(r *http.Request) string {
	if r.TLS == nil {
		return "none"
	}

	return fmt.Sprintf(
		"version=%s;cipher=%s",
		tlsVersionName(r.TLS.Version),
		tlsCipherName(r.TLS.CipherSuite),
	)
}

func tlsVersionName(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return fmt.Sprintf(
			"unknown(0x%04x)",
			version,
		)
	}
}

func tlsCipherName(cipher uint16) string {
	// Keep this intentionally lightweight.
	// The numeric ID is still useful for telemetry.
	return "0x" + strconv.FormatUint(
		uint64(cipher),
		16,
	)
}

// enqueueTelemetry adds an event to the bounded telemetry queue.
//
// The request does not wait for Redis.
func enqueueTelemetry(event TelemetryEvent) {
	select {
	case telemetryCh <- event:
	default:
		// The queue is full. We deliberately don't block the API request.
		log.Printf(
			"telemetry queue full; event dropped request_id=%s",
			event.RequestID,
		)
	}
}

// telemetryWorker is started ONCE when the gateway starts.
func telemetryWorker() {
	for event := range telemetryCh {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			2*time.Second,
		)

		err := rdb.XAdd(
			ctx,
			&redis.XAddArgs{
				Stream: telemetryStream,
				Values: map[string]interface{}{
					"event_type":       event.EventType,
					"route":            event.Route,
					"user_id_hash":     event.UserHash,
					"uri":              event.URI,
					"method":           event.Method,
					"ip":               event.IP,
					"payload_size":     event.PayloadSize,
					"timestamp":        event.Timestamp,
					"status_code":      event.StatusCode,
					"request_id":       event.RequestID,
					"user_agent_hash":  event.UserAgentHash,
					"latency_micros":   event.LatencyMicros,
					"rate_limit_state": event.RateLimitState,
					"tls_information":  event.TLSInformation,
					"response_size":    event.ResponseSize,
				},
			},
		).Err()

		cancel()

		if err != nil {
			log.Printf(
				"telemetry write failed request_id=%s error=%v",
				event.RequestID,
				err,
			)
		}
	}
}

func shortHash(hash string) string {
	if len(hash) <= 8 {
		return hash
	}

	return hash[:8]
}

func getEnv(name, fallback string) string {
	value := os.Getenv(name)

	if value == "" {
		return fallback
	}

	return value
}
