package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ClientConnection holds the result of a single fingerprinted client connection in server mode.
type ClientConnection struct {
	RemoteAddr  string
	Timestamp   time.Time
	JA3         *JA3Result
	ClientHello *ClientHello
	Error       error
}

// ServerMode starts a raw TCP listener on the given port, fingerprints each connecting
// client by intercepting their ClientHello, and streams results over the returned channel.
// Call close(stopCh) to trigger a graceful shutdown.
func ServerMode(port int, verbose bool) (<-chan *ClientConnection, chan struct{}, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, nil, fmt.Errorf("generating self-signed cert: %w", err)
	}

	// FIX: Use TLS 1.2 minimum on the server listener. The fingerprint is
	// extracted from the ClientHello, so the negotiated version does not affect
	// JA3 accuracy. Allowing TLS 1.0/1.1 on our own listener adds attack
	// surface with no benefit. Client mode intentionally keeps TLS 1.0 to
	// ensure legacy servers accept the handshake for fingerprinting purposes.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Use a raw TCP listener so we can intercept the ClientHello before TLS wrapping.
	rawListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("listen on port %d: %w", port, err)
	}

	results := make(chan *ClientConnection, 64)
	stopCh := make(chan struct{})

	go func() {
		defer close(results)

		// Closing the listener unblocks Accept() when stopCh fires.
		go func() {
			<-stopCh
			rawListener.Close()
		}()

		for {
			rawConn, err := rawListener.Accept()
			if err != nil {
				select {
				case <-stopCh:
					// Shutdown requested — exit cleanly.
				default:
					if verbose {
						fmt.Printf("[!] Accept error: %v\n", err)
					}
				}
				return
			}
			go handleServerConn(rawConn, tlsConfig, results, verbose)
		}
	}()

	return results, stopCh, nil
}

// handleServerConn processes a single incoming connection: captures the ClientHello,
// computes the JA3 fingerprint, then sends the result to the results channel.
func handleServerConn(rawConn net.Conn, tlsConfig *tls.Config, results chan<- *ClientConnection, verbose bool) {
	defer rawConn.Close()

	result := &ClientConnection{
		RemoteAddr: rawConn.RemoteAddr().String(),
		Timestamp:  time.Now(),
	}

	rawConn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck

	// Wrap to intercept raw bytes. In server mode:
	//   capture.read  = bytes received from client (ClientHello)
	//   capture.written = bytes sent to client (ServerHello)
	capture := &captureConn{Conn: rawConn}

	tlsConn := tls.Server(capture, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		result.Error = err
		if verbose {
			fmt.Printf("[!] Handshake from %s: %v\n", result.RemoteAddr, err)
		}
	}

	// Parse the ClientHello from bytes the server received.
	if len(capture.read) > 0 {
		// FIX: warn when the ClientHello hit the capture buffer ceiling.
		// A truncated ClientHello produces a wrong JA3 hash that will never
		// match any known signature.
		if capture.ReadTruncated() {
			fmt.Printf("[!] Warning: ClientHello from %s exceeded capture buffer (%d bytes) — JA3 may be incomplete\n",
				result.RemoteAddr, maxCaptureBytes)
		}
		hello, err := ParseClientHello(capture.read)
		if err != nil {
			if verbose {
				fmt.Printf("[!] ClientHello parse from %s: %v\n", result.RemoteAddr, err)
			}
		} else {
			result.ClientHello = hello
			result.JA3 = Compute(hello)
		}
	}

	results <- result
}

// generateSelfSignedCert creates a temporary ECDSA P-256 certificate valid for one year.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ViperFin TLS Fingerprinter"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, privPEM)
}
