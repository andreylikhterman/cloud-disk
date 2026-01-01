package config

import (
	"os"
	"time"
)

const (
	UploadDir = "./uploads"
	Port = ":8443"
	SFTPPort = ":2222"
	MaxUploadSize = 256 << 20 // 256MB
	JWTExpiration = 24 * time.Hour
	CertFile = "cert.pem"
	KeyFile = "key.pem"
)

var (
	DatabaseURL = "postgres://postgres:postgres@localhost:5432/fileserver?sslmode=disable"
	JWTSecret = []byte("default-insecure-secret-change-me")
)

// Config holds application configuration
type Config struct {
	UploadDir     string
	Port          string
	SFTPPort      string
	MaxUploadSize int64
	JWTExpiration time.Duration
	CertFile      string
	KeyFile       string
	DatabaseURL   string
	JWTSecret     []byte
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	return &Config{
		UploadDir:     UploadDir,
		Port:          Port,
		SFTPPort:      SFTPPort,
		MaxUploadSize: MaxUploadSize,
		JWTExpiration: JWTExpiration,
		CertFile:      CertFile,
		KeyFile:       KeyFile,
		DatabaseURL:   DatabaseURL,
		JWTSecret:     JWTSecret,
	}
}

func init() {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		DatabaseURL = url
	}
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		JWTSecret = []byte(secret)
	}
}
