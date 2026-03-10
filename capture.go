package tls

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// CaptureResult holds everything captured from a client→server TLS handshake.
type CaptureResult struct {
	Target          string
	ServerName      string
	ClientJA3       *JA3Result
	ServerJA3S      *JA3Result
	NegotiatedProto string
	CertSubject     string
	CertIssuer      string
	CertExpiry      time.Time
	TLSVersion      uint16
	NegotiatedCipher uint16
	RawClientHello  []byte
}

// ConnectAndCapture connects to a TLS server using a raw TCP connection,
// intercepts the ClientHello before crypto happens, then completes the
// handshake to gather server certificate info.
//
// Strategy: We use a custom net.Conn wrapper that captures the first
// bytes written (which will be our ClientHello) before passing them through.
func ConnectAndCapture(host string, port int, verbose bool) (*CaptureResult, error) {
	target := fmt.Sprintf("%s:%d", host, port)

	if verbose {
		fmt.Printf("[*] Connecting to %s\n", target)
	}

	result := &CaptureResult{
		Target:     target,
		ServerName: host,
	}

	// Step 1: Raw TCP connection with capture wrapper
	rawConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %w", err)
	}
	defer rawConn.Close()

	// Wrap the connection to intercept bytes
	capture := &captureConn{Conn: rawConn}

	// Step 2: Perform TLS handshake through the capture wrapper
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false, // Verify cert normally
		MinVersion:         tls.VersionTLS10,
		// Include a wide range of cipher suites so our JA3 is representative
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		},
	}

	tlsConn := tls.Client(capture, tlsConfig)

	if verbose {
		fmt.Println("[*] Performing TLS handshake...")
	}

	err = tlsConn.Handshake()
	if err != nil {
		// Even if handshake fails (e.g. cert verify), we may have captured the ClientHello
		if verbose {
			fmt.Printf("[!] Handshake error (may still have ClientHello): %v\n", err)
		}
	}

	// Step 3: Parse the captured ClientHello
	if len(capture.written) > 0 {
		result.RawClientHello = capture.written

		if verbose {
			fmt.Printf("[*] Captured %d bytes of ClientHello\n", len(capture.written))
		}

		hello, parseErr := ParseClientHello(capture.written)
		if parseErr != nil {
			if verbose {
				fmt.Printf("[!] ClientHello parse error: %v\n", parseErr)
			}
		} else {
			result.ClientJA3 = Compute(hello)
			if hello.ServerName != "" {
				result.ServerName = hello.ServerName
			}
		}
	}

	// Step 4: Extract server cert info if handshake succeeded
	if err == nil {
		state := tlsConn.ConnectionState()
		result.TLSVersion = state.Version
		result.NegotiatedCipher = state.CipherSuite
		result.NegotiatedProto = state.NegotiatedProtocol

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			result.CertSubject = cert.Subject.CommonName
			result.CertIssuer = cert.Issuer.CommonName
			result.CertExpiry = cert.NotAfter
		}

		// Capture ServerHello from received bytes
		if len(capture.read) > 0 {
			serverHello, shErr := ParseServerHello(capture.read)
			if shErr == nil {
				result.ServerJA3S = ComputeJA3S(serverHello)
			}
		}
	}

	return result, nil
}

// captureConn wraps a net.Conn and records bytes written (our ClientHello)
// and bytes read (server's ServerHello) without modifying them.
type captureConn struct {
	net.Conn
	written []byte
	read    []byte
}

func (c *captureConn) Write(b []byte) (n int, err error) {
	// Capture outgoing bytes (our ClientHello will be here)
	c.written = append(c.written, b...)
	return c.Conn.Write(b)
}

func (c *captureConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && len(c.read) < 4096 {
		// Only capture first 4KB (enough for ServerHello)
		c.read = append(c.read, b[:n]...)
	}
	return n, err
}

// TLSVersionName returns a human-readable TLS version string.
func TLSVersionName(version uint16) string {
	versions := map[uint16]string{
		0x0300: "SSL 3.0",
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
	}
	if name, ok := versions[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", version)
}
