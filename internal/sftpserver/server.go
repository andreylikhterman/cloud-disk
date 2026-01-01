package sftpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"fileserver/internal/auth"
	"fileserver/internal/config"
	"fileserver/internal/db"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	config    *ssh.ServerConfig
	listener  net.Listener
	cfg       *config.Config
	uploadDir string
}

// NewServer creates a new SFTP server instance
func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		uploadDir: cfg.UploadDir,
	}

	hostKey, err := s.loadOrGenerateHostKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: s.passwordAuthCallback,
		ServerVersion:    "SSH-2.0-CloudDisk-SFTP",
	}
	sshConfig.AddHostKey(hostKey)

	s.config = sshConfig

	return s, nil
}

// Start starts the SFTP server on the specified port
func (s *Server) Start(port string) error {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", port, err)
	}
	s.listener = listener

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Shutdown gracefully shuts down the SFTP server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// passwordAuthCallback handles password authentication
func (s *Server) passwordAuthCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()

	user, err := db.GetUserByUsername(username)
	if err != nil {
		log.Printf("SFTP auth failed for user %s: user not found", username)
		return nil, fmt.Errorf("authentication failed")
	}

	if !auth.CheckPasswordHash(string(password), user.PasswordHash) {
		log.Printf("SFTP auth failed for user %s: invalid password", username)
		return nil, fmt.Errorf("authentication failed")
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id":  fmt.Sprintf("%d", user.ID),
			"username": user.Username,
		},
	}, nil
}

// loadOrGenerateHostKey loads existing host key or generates a new one
func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	hostKeyDir := "sftp_keys"
	hostKeyPath := filepath.Join(hostKeyDir, "sftp_host_key")

	if err := os.MkdirAll(hostKeyDir, 0755); err != nil {
		log.Printf("Warning: failed to create host key directory: %v", err)
	}

	if _, err := os.Stat(hostKeyPath); err == nil {
		keyBytes, err := os.ReadFile(hostKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read host key: %w", err)
		}

		key, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}

		log.Println("Loaded existing SFTP host key")
		return key, nil
	}

	log.Println("Generating new SFTP host key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	keyFile, err := os.Create(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create host key file: %w", err)
	}
	defer keyFile.Close()

	if err := os.Chmod(hostKeyPath, 0600); err != nil {
		return nil, fmt.Errorf("failed to set host key permissions: %w", err)
	}

	if err := pem.Encode(keyFile, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("failed to write host key: %w", err)
	}

	key, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	log.Println("Generated new SFTP host key")
	return key, nil
}

// handleConnection handles an incoming SSH connection
func (s *Server) handleConnection(netConn net.Conn) {
	defer netConn.Close()

	conn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer conn.Close()

	userID := conn.Permissions.Extensions["user_id"]
	username := conn.Permissions.Extensions["username"]

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		go s.handleChannel(channel, requests, userID, username)
	}
}

// handleChannel handles SSH channel requests (SFTP subsystem)
func (s *Server) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request, userID, username string) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "subsystem":
			if len(req.Payload) < 4 {
				req.Reply(false, nil)
				continue
			}

			subsystemLen := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 | uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
			if len(req.Payload) < int(4+subsystemLen) {
				req.Reply(false, nil)
				continue
			}
			subsystem := string(req.Payload[4 : 4+subsystemLen])

			if subsystem == "sftp" {
				req.Reply(true, nil)
				s.handleSFTP(channel, userID, username)
				return
			} else {
				req.Reply(false, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleSFTP handles SFTP subsystem
func (s *Server) handleSFTP(channel ssh.Channel, userID, username string) {
	fs := NewUserFileSystem(userID, username, s.uploadDir)

	handlers := sftp.Handlers{
		FileGet:  fs,
		FilePut:  fs,
		FileCmd:  fs,
		FileList: fs,
	}

	server := sftp.NewRequestServer(channel, handlers)
	if err := server.Serve(); err != nil {
		log.Printf("SFTP server finished: %v", err)
	}
}
