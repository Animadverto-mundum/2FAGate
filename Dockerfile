FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /auth-service .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /auth-service /usr/local/bin/auth-service
EXPOSE 8080
ENTRYPOINT ["auth-service"]
