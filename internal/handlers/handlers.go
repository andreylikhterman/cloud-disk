package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"fileserver/internal/auth"
	"fileserver/internal/config"
	"fileserver/internal/db"
	"fileserver/internal/models"
)

func SendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func Index(templatePath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, templatePath)
	}
}

func RegisterPage(templatePath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, templatePath)
	}
}

func Register(templatePath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, templatePath)
			return
		}

		if r.Method != http.MethodPost {
			SendJSON(w, http.StatusMethodNotAllowed, models.Response{
				Success: false,
				Message: "Method not allowed",
			})
			return
		}

		var req models.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			SendJSON(w, http.StatusBadRequest, models.Response{
				Success: false,
				Message: "Invalid request body",
			})
			return
		}

		user, err := auth.RegisterUser(req.Username, req.Password)
		if err != nil {
			status := http.StatusBadRequest
			if err.Error() == "username already exists" {
				status = http.StatusConflict
			}
			SendJSON(w, status, models.Response{
				Success: false,
				Message: err.Error(),
			})
			return
		}

		SendJSON(w, http.StatusCreated, models.Response{
			Success: true,
			Message: "User registered successfully",
			Data: map[string]interface{}{
				"username":  user.Username,
				"createdAt": user.CreatedAt,
			},
		})
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	user, err := auth.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		SendJSON(w, http.StatusUnauthorized, models.Response{
			Success: false,
			Message: "Invalid username or password",
		})
		return
	}

	token, expiresAt, err := auth.CreateToken(user)
	if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to generate token",
		})
		return
	}

	SendJSON(w, http.StatusOK, models.Response{
		Success: true,
		Message: "Login successful",
		Data: models.LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt,
			Username:  user.Username,
		},
	})
}

func Upload(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	userIDStr := r.Header.Get("X-User-ID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodPost {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, config.MaxUploadSize)
	if err := r.ParseMultipartForm(config.MaxUploadSize); err != nil {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "File too large or bad request",
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Failed to read file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	buff := make([]byte, 512)
	if _, err := file.Read(buff); err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to read file content",
		})
		return
	}

	if _, err := file.Seek(0, 0); err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to reset file pointer",
		})
		return
	}

	fileType := http.DetectContentType(buff)
	allowedTypes := map[string]bool{
		"image/jpeg":                true,
		"image/png":                 true,
		"image/gif":                 true,
		"application/pdf":           true,
		"text/plain; charset=utf-8": true,
		"application/zip":           true,
		"application/octet-stream":  true,
	}

	if !allowedTypes[fileType] {
		log.Printf("Blocked upload of type %s by %s\n", fileType, username)
	}

	ext := filepath.Ext(header.Filename)
	storageName := fmt.Sprintf("%d_%d%s", userID, time.Now().UnixNano(), ext)
	storagePath := filepath.Join(config.UploadDir, storageName)

	dst, err := os.Create(storagePath)
	if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to create file: " + err.Error(),
		})
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to save file: " + err.Error(),
		})
		return
	}

	_, err = db.DB.Exec(
		"INSERT INTO files (user_id, filename, path, size) VALUES ($1, $2, $3, $4)",
		userID, header.Filename, storageName, header.Size,
	)
	if err != nil {
		os.Remove(storagePath)
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to save file metadata: " + err.Error(),
		})
		return
	}

	log.Printf("File uploaded by %s: %s (%d bytes)\n", username, header.Filename, header.Size)
	SendJSON(w, http.StatusOK, models.Response{
		Success: true,
		Message: "File uploaded successfully",
		Data: map[string]interface{}{
			"filename": header.Filename,
			"size":     header.Size,
			"user":     username,
		},
	})
}

func Download(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	userIDStr := r.Header.Get("X-User-ID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodGet {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	filename := filepath.Base(r.URL.Path[len("/download/"):])
	if filename == "" || filename == "." {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Invalid filename",
		})
		return
	}

	var storageName string
	var size int64
	err := db.DB.QueryRow(
		"SELECT path, size FROM files WHERE user_id = $1 AND filename = $2",
		userID, filename,
	).Scan(&storageName, &size)

	if err == sql.ErrNoRows {
		SendJSON(w, http.StatusNotFound, models.Response{
			Success: false,
			Message: "File not found",
		})
		return
	} else if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Database error: " + err.Error(),
		})
		return
	}

	filePath := filepath.Join(config.UploadDir, storageName)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))

	http.ServeFile(w, r, filePath)
	log.Printf("File downloaded by %s: %s (%d bytes)\n", username, filename, size)
}

func ListFiles(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	userIDStr := r.Header.Get("X-User-ID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodGet {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	rows, err := db.DB.Query("SELECT filename, size, created_at FROM files WHERE user_id = $1 ORDER BY created_at DESC", userID)
	if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Database error: " + err.Error(),
		})
		return
	}
	defer rows.Close()

	files := make([]models.FileInfo, 0)
	for rows.Next() {
		var f models.FileInfo
		if err := rows.Scan(&f.Name, &f.Size, &f.ModTime); err != nil {
			continue
		}
		f.IsDir = false
		files = append(files, f)
	}

	log.Printf("Files listed by %s: %d files\n", username, len(files))
	SendJSON(w, http.StatusOK, models.Response{
		Success: true,
		Message: fmt.Sprintf("Found %d files", len(files)),
		Data:    files,
	})
}

func Delete(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	userIDStr := r.Header.Get("X-User-ID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodDelete {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	filename := filepath.Base(r.URL.Path[len("/delete/"):])
	if filename == "" || filename == "." {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Invalid filename",
		})
		return
	}

	var storageName string
	err := db.DB.QueryRow(
		"SELECT path FROM files WHERE user_id = $1 AND filename = $2",
		userID, filename,
	).Scan(&storageName)

	if err == sql.ErrNoRows {
		SendJSON(w, http.StatusNotFound, models.Response{
			Success: false,
			Message: "File not found",
		})
		return
	}

	_, err = db.DB.Exec("DELETE FROM files WHERE user_id = $1 AND filename = $2", userID, filename)
	if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Database error: " + err.Error(),
		})
		return
	}

	filePath := filepath.Join(config.UploadDir, storageName)
	os.Remove(filePath)

	log.Printf("File deleted by %s: %s\n", username, filename)
	SendJSON(w, http.StatusOK, models.Response{
		Success: true,
		Message: "File deleted successfully",
		Data: map[string]string{
			"filename": filename,
			"user":     username,
		},
	})
}

func Rename(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	userIDStr := r.Header.Get("X-User-ID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodPost {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var req models.RenameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	if req.OldName == "" || req.NewName == "" {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Both old and new names are required",
		})
		return
	}

	result, err := db.DB.Exec(
		"UPDATE files SET filename = $1 WHERE user_id = $2 AND filename = $3",
		req.NewName, userID, req.OldName,
	)
	if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Database error: " + err.Error(),
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		SendJSON(w, http.StatusNotFound, models.Response{
			Success: false,
			Message: "File not found",
		})
		return
	}

	log.Printf("File renamed by %s: %s -> %s\n", username, req.OldName, req.NewName)
	SendJSON(w, http.StatusOK, models.Response{
		Success: true,
		Message: "File renamed successfully",
		Data: map[string]string{
			"oldName": req.OldName,
			"newName": req.NewName,
		},
	})
}

func ShareFile(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get("X-User-ID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodPost {
		SendJSON(w, http.StatusMethodNotAllowed, models.Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var req models.ShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	if req.Filename == "" {
		SendJSON(w, http.StatusBadRequest, models.Response{
			Success: false,
			Message: "Filename is required",
		})
		return
	}

	var fileID int
	err := db.DB.QueryRow("SELECT id FROM files WHERE user_id = $1 AND filename = $2", userID, req.Filename).Scan(&fileID)
	if err == sql.ErrNoRows {
		SendJSON(w, http.StatusNotFound, models.Response{
			Success: false,
			Message: "File not found",
		})
		return
	} else if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Database error: " + err.Error(),
		})
		return
	}

	var token string
	err = db.DB.QueryRow("INSERT INTO shared_links (file_id) VALUES ($1) RETURNING token", fileID).Scan(&token)
	if err != nil {
		SendJSON(w, http.StatusInternalServerError, models.Response{
			Success: false,
			Message: "Failed to create share link: " + err.Error(),
		})
		return
	}

	SendJSON(w, http.StatusOK, models.Response{
		Success: true,
		Message: "Share link created",
		Data: map[string]string{
			"token": token,
		},
	})
}

func GetSharedFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := filepath.Base(r.URL.Path)
	if token == "" || token == "s" {
		http.NotFound(w, r)
		return
	}

	var filename, storageName string
	var size int64
	err := db.DB.QueryRow(`
		SELECT f.filename, f.path, f.size
		FROM files f
		JOIN shared_links s ON f.id = s.file_id
		WHERE s.token = $1`,
		token,
	).Scan(&filename, &storageName, &size)

	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	filePath := filepath.Join(config.UploadDir, storageName)
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "File not found on disk", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))

	io.Copy(w, file)
}
