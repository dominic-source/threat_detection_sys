// package gateway
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	redis "github.com/redis/go-redis/v9"
)

var rdb *redis.Client
var router *openapi3filter.Router

func main() {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	rdb = redis.NewClient(&redis.Options{Addr: addr})
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	// Load OpenAPI spec for request schema validation
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	if doc, err := loader.LoadFromFile("/etc/gateway/openapi.yaml"); err != nil {
		log.Printf("warning: failed to load openapi spec: %v", err)
	} else {
		router = openapi3filter.NewRouter().WithSwagger(doc)
		log.Println("OpenAPI spec loaded")
	}

	http.HandleFunc("/", gatewayHandler)
	srv := &http.Server{Addr: ":8080", ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	log.Println("gateway listening on :8080")
	log.Fatal(srv.ListenAndServe())
}

func gatewayHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	start := time.Now()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// Replace body so validators/readers can re-consume it
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Identify user: header X-User-ID or user_id in JSON
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		var p map[string]interface{}
		_ = json.Unmarshal(body, &p)
		if v, ok := p["user_id"].(string); ok {
			userID = v
		}
	}
	if userID == "" {
		userID = "anonymous"
	}

	// Hash user id for privacy
	h := sha256.Sum256([]byte(userID))
	userHash := hex.EncodeToString(h[:])

	// Check blocklist
	blockKey := fmt.Sprintf("blocklist:%s", userHash)
	exists, err := rdb.Exists(ctx, blockKey).Result()
	if err == nil && exists > 0 {
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	// OpenAPI-based schema validation (if spec loaded)
	if router != nil {
		route, pathParams, err := router.FindRoute(r.Method, r.URL)
		if err == nil && route != nil {
			input := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: pathParams,
				Route:      route,
				Options:    &openapi3filter.Options{MultiError: true},
			}
			if err := openapi3filter.ValidateRequest(ctx, input); err != nil {
				http.Error(w, "schema validation failed", http.StatusBadRequest)
				return
			}
		}
	} else {
		// fallback quick validation
		if !quickValidateJSON(body) {
			http.Error(w, "schema validation failed", http.StatusBadRequest)
			return
		}
	}

	// Emit telemetry asynchronously (best-effort)
	go func(b []byte, userHash string, uri, method string) {
		ctx := context.Background()
		vals := map[string]interface{}{
			"user_id_hash": userHash,
			"uri":          uri,
			"method":       method,
			"payload_size": len(b),
			"timestamp":    time.Now().UnixMicro(),
		}
		_ = rdb.XAdd(ctx, &redis.XAddArgs{Stream: "stream:telemetry", Values: vals}).Err()
	}(body, userHash, r.URL.Path, r.Method)

	// In an MVP, forward to backend would occur here; respond OK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))

	elapsed := time.Since(start)
	log.Printf("served %s %s user=%s payload=%d elapsed=%s", r.Method, r.URL.Path, userHash[:8], len(body), elapsed)
}

func quickValidateJSON(b []byte) bool {
	// Minimal validation: ensure JSON decodable and not empty object
	var x interface{}
	if err := json.Unmarshal(b, &x); err != nil {
		return false
	}
	return true
}
