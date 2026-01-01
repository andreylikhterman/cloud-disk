package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Claims struct {
	UserID   int64  `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}

type File struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"userId"`
	Filename  string    `json:"filename"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	HashMD5   string    `json:"hashMd5,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	Username  string    `json:"username"`
}

type RenameRequest struct {
	OldName string `json:"oldName"`
	NewName string `json:"newName"`
}

type ShareRequest struct {
	Filename string `json:"filename"`
}

type UserQuota struct {
	UserID         int64     `json:"userId"`
	StorageQuota   int64     `json:"storageQuota"`
	StorageUsed    int64     `json:"storageUsed"`
	FileCountQuota int       `json:"fileCountQuota"`
	FileCountUsed  int       `json:"fileCountUsed"`
	MaxFileSize    int64     `json:"maxFileSize"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type QuotaResponse struct {
	Storage struct {
		Used            int64   `json:"used"`
		Quota           int64   `json:"quota"`
		UsedPercent     float64 `json:"usedPercent"`
		Available       int64   `json:"available"`
		UsedFormatted   string  `json:"usedFormatted"`
		QuotaFormatted  string  `json:"quotaFormatted"`
	} `json:"storage"`
	FileCount struct {
		Used        int     `json:"used"`
		Quota       int     `json:"quota"`
		UsedPercent float64 `json:"usedPercent"`
		Available   int     `json:"available"`
	} `json:"fileCount"`
	MaxFileSize          int64  `json:"maxFileSize"`
	MaxFileSizeFormatted string `json:"maxFileSizeFormatted"`
}
