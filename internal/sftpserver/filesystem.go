package sftpserver

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"fileserver/internal/db"
	"fileserver/internal/models"

	"github.com/pkg/sftp"
)

// UserFileSystem implements sftp.Handlers interface
type UserFileSystem struct {
	userID    string
	username  string
	uploadDir string
}

// NewUserFileSystem creates a new user-specific filesystem handler
func NewUserFileSystem(userID, username, uploadDir string) *UserFileSystem {
	return &UserFileSystem{
		userID:    userID,
		username:  username,
		uploadDir: uploadDir,
	}
}

// Fileread implements sftp.FileReader interface
func (fs *UserFileSystem) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	userIDInt, _ := strconv.Atoi(fs.userID)
	filename := filepath.Base(r.Filepath)

	file, err := db.GetFileByUserAndFilename(userIDInt, filename)
	if err != nil {
		log.Printf("File not found in database: %s", filename)
		return nil, os.ErrNotExist
	}

	physicalPath := filepath.Join(fs.uploadDir, file.Path)
	f, err := os.Open(physicalPath)
	if err != nil {
		log.Printf("Failed to open file %s: %v", physicalPath, err)
		return nil, err
	}

	return f, nil
}

// Filewrite implements sftp.FileWriter interface
func (fs *UserFileSystem) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	filename := filepath.Base(r.Filepath)

	timestamp := time.Now().UnixNano()
	ext := filepath.Ext(filename)
	physicalName := fmt.Sprintf("%s_%d%s", fs.userID, timestamp, ext)
	physicalPath := filepath.Join(fs.uploadDir, physicalName)

	if err := os.MkdirAll(fs.uploadDir, 0755); err != nil {
		log.Printf("Failed to create upload directory: %v", err)
		return nil, err
	}

	var f *os.File
	var err error

	const (
		sshFxfRead   = 0x00000001
		sshFxfWrite  = 0x00000002
		sshFxfAppend = 0x00000004
		sshFxfCreat  = 0x00000008
		sshFxfTrunc  = 0x00000010
		sshFxfExcl   = 0x00000020
	)

	if r.Flags&sshFxfCreat != 0 || r.Flags&sshFxfTrunc != 0 {
		f, err = os.Create(physicalPath)
		if err != nil {
			log.Printf("Failed to create file: %v", err)
			return nil, err
		}
	} else {
		f, err = os.OpenFile(physicalPath, int(r.Flags), 0644)
		if err != nil {
			log.Printf("Failed to open file: %v", err)
			return nil, err
		}
	}

	return &fileWriter{
		File:         f,
		fs:           fs,
		filename:     filename,
		physicalName: physicalName,
		physicalPath: physicalPath,
	}, nil
}

// Filecmd implements sftp.FileCmder interface
func (fs *UserFileSystem) Filecmd(r *sftp.Request) error {
	userIDInt, _ := strconv.Atoi(fs.userID)

	switch r.Method {
	case "Remove":
		filename := filepath.Base(r.Filepath)

		file, err := db.GetFileByUserAndFilename(userIDInt, filename)
		if err != nil {
			return os.ErrNotExist
		}

		fileSize := file.Size

		physicalPath := filepath.Join(fs.uploadDir, file.Path)
		if err := os.Remove(physicalPath); err != nil {
			log.Printf("Failed to remove physical file %s: %v", physicalPath, err)
		}

		if err := db.DeleteFile(userIDInt, filename); err != nil {
			return err
		}

		if err := db.UpdateQuotaUsage(userIDInt, -fileSize, -1); err != nil {
			log.Printf("Warning: failed to update quota for user %d: %v", userIDInt, err)
		}

		return nil

	case "Rename":
		oldFilename := filepath.Base(r.Filepath)
		newFilename := filepath.Base(r.Target)

		if err := db.RenameFile(userIDInt, oldFilename, newFilename); err != nil {
			return err
		}

		return nil

	case "Mkdir":
		log.Printf("Mkdir requested but not supported: %s", r.Filepath)
		return nil

	case "Rmdir":
		log.Printf("Rmdir requested but not supported: %s", r.Filepath)
		return nil

	case "Setstat":
		return nil

	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (fs *UserFileSystem) Filestat(r *sftp.Request) (os.FileInfo, error) {
	if r.Filepath == "/" {
		return &virtualFileInfo{
			name:    "/",
			size:    0,
			modTime: time.Now(),
			isDir:   true,
		}, nil
	}

	userIDInt, _ := strconv.Atoi(fs.userID)
	filename := filepath.Base(r.Filepath)

	file, err := db.GetFileByUserAndFilename(userIDInt, filename)
	if err != nil {
		return nil, os.ErrNotExist
	}

	return &virtualFileInfo{
		name:    file.Filename,
		size:    file.Size,
		modTime: file.CreatedAt,
		isDir:   false,
	}, nil
}

func (fs *UserFileSystem) Lstat(r *sftp.Request) (os.FileInfo, error) {
	return fs.Filestat(r)
}

func (fs *UserFileSystem) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	userIDInt, _ := strconv.Atoi(fs.userID)
	files, err := db.GetFilesByUserID(userIDInt)
	if err != nil {
		log.Printf("Failed to list files: %v", err)
		return nil, err
	}

	var fileInfos []os.FileInfo
	for _, f := range files {
		stat, err := os.Stat(f.Path)
		if err != nil {
			log.Printf("Warning: could not stat file %s: %v", f.Path, err)
			fileInfos = append(fileInfos, &virtualFileInfo{
				name:    f.Filename,
				size:    f.Size,
				modTime: f.CreatedAt,
				isDir:   false,
			})
			continue
		}

		fileInfos = append(fileInfos, &virtualFileInfo{
			name:    f.Filename,
			size:    stat.Size(),
			modTime: stat.ModTime(),
			isDir:   false,
		})
	}

	return listerat(fileInfos), nil
}

// fileWriter wraps os.File to handle database operations on close
type fileWriter struct {
	*os.File
	fs           *UserFileSystem
	filename     string
	physicalName string
	physicalPath string
	closed       bool
}

func (fw *fileWriter) Close() error {
	if fw.closed {
		return nil
	}
	fw.closed = true

	if err := fw.File.Close(); err != nil {
		return err
	}

	stat, err := os.Stat(fw.physicalPath)
	if err != nil {
		log.Printf("Failed to stat uploaded file: %v", err)
		return err
	}

	userIDInt, _ := strconv.Atoi(fw.fs.userID)
	hasQuota, err := db.CheckQuota(userIDInt, stat.Size())
	if err != nil {
		log.Printf("Failed to check quota: %v", err)
		os.Remove(fw.physicalPath)
		return fmt.Errorf("failed to check quota")
	}
	if !hasQuota {
		log.Printf("Quota exceeded for user %s, file size: %d", fw.fs.username, stat.Size())
		os.Remove(fw.physicalPath)
		return fmt.Errorf("quota exceeded")
	}

	hashMD5, err := calculateFileMD5(fw.physicalPath)
	if err != nil {
		log.Printf("Failed to calculate MD5 hash: %v", err)
		hashMD5 = ""
	}

	fileModel := &models.File{
		UserID:   int64(userIDInt),
		Filename: fw.filename,
		Path:     fw.physicalName,
		Size:     stat.Size(),
		HashMD5:  hashMD5,
	}

	_, err = db.GetFileByUserAndFilename(userIDInt, fw.filename)
	if err == nil {
		db.DeleteFile(userIDInt, fw.filename)
	}

	if err := db.CreateFile(fileModel); err != nil {
		log.Printf("Failed to save file to database: %v", err)
		os.Remove(fw.physicalPath)
		return err
	}

	if err := db.UpdateQuotaUsage(userIDInt, stat.Size(), 1); err != nil {
		log.Printf("Warning: failed to update quota for user %d: %v", userIDInt, err)
	}

	return nil
}

// virtualFileInfo implements os.FileInfo interface
type virtualFileInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
}

func (fi *virtualFileInfo) Name() string       { return fi.name }
func (fi *virtualFileInfo) Size() int64        { return fi.size }
func (fi *virtualFileInfo) Mode() os.FileMode {
	if fi.isDir {
		return 0755 | os.ModeDir
	}
	return 0644
}
func (fi *virtualFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *virtualFileInfo) IsDir() bool        { return fi.isDir }
func (fi *virtualFileInfo) Sys() interface{}   { return nil }

// listerat implements sftp.ListerAt interface
type listerat []os.FileInfo

func (l listerat) ListAt(f []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}

	n := copy(f, l[offset:])
	if n < len(f) {
		return n, io.EOF
	}
	return n, nil
}

// calculateFileMD5 calculates MD5 hash of a file
func calculateFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := md5.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
