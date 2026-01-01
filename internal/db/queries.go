package db

import (
	"database/sql"

	"fileserver/internal/models"
)

// GetUserByUsername retrieves a user by username
func GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := DB.QueryRow(
		"SELECT id, username, password_hash, created_at FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetFileByUserAndFilename retrieves a file by user ID and filename
func GetFileByUserAndFilename(userID int, filename string) (*models.File, error) {
	var file models.File
	err := DB.QueryRow(
		"SELECT id, user_id, filename, path, size, hash_md5, created_at FROM files WHERE user_id = $1 AND filename = $2",
		userID, filename,
	).Scan(&file.ID, &file.UserID, &file.Filename, &file.Path, &file.Size, &file.HashMD5, &file.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &file, nil
}

// GetFilesByUserID retrieves all files for a user
func GetFilesByUserID(userID int) ([]*models.File, error) {
	rows, err := DB.Query(
		"SELECT id, user_id, filename, path, size, hash_md5, created_at FROM files WHERE user_id = $1 ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		var file models.File
		if err := rows.Scan(&file.ID, &file.UserID, &file.Filename, &file.Path, &file.Size, &file.HashMD5, &file.CreatedAt); err != nil {
			return nil, err
		}
		files = append(files, &file)
	}

	return files, rows.Err()
}

// CreateFile creates a new file record
func CreateFile(file *models.File) error {
	_, err := DB.Exec(
		"INSERT INTO files (user_id, filename, path, size, hash_md5) VALUES ($1, $2, $3, $4, $5)",
		file.UserID, file.Filename, file.Path, file.Size, file.HashMD5,
	)
	return err
}

// DeleteFile deletes a file record
func DeleteFile(userID int, filename string) error {
	result, err := DB.Exec(
		"DELETE FROM files WHERE user_id = $1 AND filename = $2",
		userID, filename,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// RenameFile renames a file (updates the filename field)
func RenameFile(userID int, oldFilename, newFilename string) error {
	result, err := DB.Exec(
		"UPDATE files SET filename = $1 WHERE user_id = $2 AND filename = $3",
		newFilename, userID, oldFilename,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// GetUserQuota retrieves quota information for a user
func GetUserQuota(userID int) (*models.UserQuota, error) {
	var quota models.UserQuota
	err := DB.QueryRow(
		"SELECT user_id, storage_quota, storage_used, file_count_quota, file_count_used, max_file_size, updated_at FROM user_quotas WHERE user_id = $1",
		userID,
	).Scan(&quota.UserID, &quota.StorageQuota, &quota.StorageUsed, &quota.FileCountQuota, &quota.FileCountUsed, &quota.MaxFileSize, &quota.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &quota, nil
}

// CheckQuota checks if user has enough quota for a file
func CheckQuota(userID int, fileSize int64) (bool, error) {
	quota, err := GetUserQuota(userID)
	if err != nil {
		return false, err
	}

	if quota.StorageUsed+fileSize > quota.StorageQuota {
		return false, nil
	}

	if fileSize > quota.MaxFileSize {
		return false, nil
	}

	return true, nil
}

// UpdateQuotaUsage updates quota usage (can be positive or negative delta)
func UpdateQuotaUsage(userID int, sizeDelta int64, countDelta int) error {
	_, err := DB.Exec(
		"UPDATE user_quotas SET storage_used = storage_used + $1, file_count_used = file_count_used + $2, updated_at = CURRENT_TIMESTAMP WHERE user_id = $3",
		sizeDelta, countDelta, userID,
	)
	return err
}
