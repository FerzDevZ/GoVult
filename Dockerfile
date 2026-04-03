# GoVult v2.0 Dockerfile
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o govult ./cmd/scanner/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/govult .
COPY --from=builder /app/templates ./templates

ENTRYPOINT ["./govult"]
CMD ["--help"]
