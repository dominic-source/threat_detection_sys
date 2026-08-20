curl -X POST http://localhost:8080/test \
  -H "Content-Type: application/json" \
  -H "X-User-ID: alice" \
  -d '{"user_id":"alice","foo":"bar"}'


curl -X POST http://localhost:8080/test -H "Content-Type: application/json" -H "X-User-ID: alice" -d '{"user_id":"alice","foo":"bar"}'




<!-- gateway/
├── main.go
├── config.go
├── handler.go
├── auth.go
├── ratelimit.go
├── blocklist.go
├── openapi.go
├── proxy.go
├── telemetry.go
├── identity.go
├── requestid.go
└── ip.go -->