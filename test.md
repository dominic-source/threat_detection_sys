curl -X POST http://localhost:8080/test \
  -H "Content-Type: application/json" \
  -H "X-User-ID: alice" \
  -d '{"user_id":"alice","foo":"bar"}'


curl -X POST http://localhost:8080/test -H "Content-Type: application/json" -H "X-User-ID: alice" -d '{"user_id":"alice","foo":"bar"}'

