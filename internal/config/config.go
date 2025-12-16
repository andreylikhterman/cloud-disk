package config

import (
	"os"
	"time"
)

const (
	UploadDir = "./uploads"
	Port = ":8443"
	MaxUploadSize = 100 << 20
	JWTExpiration = 24 * time.Hour
	CertFile = "cert.pem"
	KeyFile = "key.pem"
)

var (
	DatabaseURL = "postgres://postgres:postgres@localhost:5432/fileserver?sslmode=disable"
	JWTSecret = []byte("default-insecure-secret-change-me")
)

func init() {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		DatabaseURL = url
	}
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		JWTSecret = []byte(secret)
	}
}
