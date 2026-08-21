FROM golang:1.26.5-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN go build -o /usr/local/bin/gateway ./

FROM alpine:3.18
COPY --from=build /usr/local/bin/gateway /usr/local/bin/gateway
COPY --from=build /app/openapi.yaml /etc/gateway/openapi.yaml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
