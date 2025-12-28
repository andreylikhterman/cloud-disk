package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/time/rate"

	"fileserver/internal/auth"
	"fileserver/internal/config"
	"fileserver/internal/db"
	"fileserver/internal/handlers"
	"fileserver/internal/middleware"
	"fileserver/internal/tls"
)

func main() {
	if err := os.MkdirAll(config.UploadDir, 0755); err != nil {
		log.Fatal("Failed to create upload directory:", err)
	}

	if err := db.InitDB(config.DatabaseURL); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	limiter := middleware.NewRateLimiter(rate.Limit(5), 10)

	templatePath := filepath.Join("web", "templates", "index.html")

	mux := http.NewServeMux()

	mux.HandleFunc("/", handlers.Index(templatePath))
	mux.HandleFunc("/register", handlers.Register(filepath.Join("web", "templates", "register.html")))
	mux.HandleFunc("/login", handlers.Login)

	fs := http.FileServer(http.Dir("web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	mux.HandleFunc("/upload", auth.Middleware(handlers.Upload))
	mux.HandleFunc("/download/", auth.Middleware(handlers.Download))
	mux.HandleFunc("/files", auth.Middleware(handlers.ListFiles))
	mux.HandleFunc("/delete/", auth.Middleware(handlers.Delete))
	mux.HandleFunc("/rename", auth.Middleware(handlers.Rename))
	mux.HandleFunc("/share", auth.Middleware(handlers.ShareFile))
	mux.HandleFunc("/s/", handlers.GetSharedFile)

	handler := middleware.SecurityHeaders(limiter.Limit(mux))

	log.Printf("Secure file server starting on https://localhost%s\n", config.Port)
	log.Printf("Upload directory: %s\n", config.UploadDir)
	log.Printf("JWT token expiration: %v\n", config.JWTExpiration)
	log.Println("Using self-signed certificate - browser will show security warning")

	if err := tls.GenerateCertificates(); err != nil {
		log.Fatal("Failed to generate certificates:", err)
	}

	if err := http.ListenAndServeTLS(config.Port, config.CertFile, config.KeyFile, handler); err != nil {
		log.Fatal("Server error:", err)
	}
}
