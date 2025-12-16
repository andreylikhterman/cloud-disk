package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"time"

	"fileserver/internal/config"
)

func GenerateCertificates() error {
	if _, err := os.Stat(config.CertFile); err == nil {
		if _, err := os.Stat(config.KeyFile); err == nil {
			log.Println("Using existing TLS certificates")
			return nil
		}
	}

	log.Println("Generating self-signed TLS certificate...")

	cmd := `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost" 2>/dev/null`

	if err := executeCommand(cmd); err != nil {
		return generateCertificatesGo()
	}

	log.Println("TLS certificate generated successfully")
	return nil
}

func executeCommand(cmd string) error {
	var shellCmd []string
	if os.PathSeparator == '\\' {
		shellCmd = []string{"cmd", "/C", cmd}
	} else {
		shellCmd = []string{"sh", "-c", cmd}
	}

	process := &exec.Cmd{
		Path:   shellCmd[0],
		Args:   shellCmd,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	path, err := exec.LookPath(shellCmd[0])
	if err != nil {
		return err
	}
	process.Path = path

	return process.Run()
}

func generateCertificatesGo() error {
	log.Println("OpenSSL not found, using Go crypto library")

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.Create(config.CertFile)
	if err != nil {
		return fmt.Errorf("failed to create cert.pem: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	keyOut, err := os.OpenFile(config.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key.pem: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	log.Println("TLS certificate generated successfully using Go crypto")
	return nil
}
