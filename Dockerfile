FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o fileserver cmd/fileserver/main.go

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/fileserver .

COPY web ./web

RUN mkdir -p uploads sftp_keys && \
    adduser -D -H -h /app appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8443

CMD ["./fileserver"]
