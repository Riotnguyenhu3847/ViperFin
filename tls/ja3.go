package tls

import (
	"crypto/md5"
	"fmt"
	"strconv"
	"strings"
)

// GREASE values are excluded from JA3 computation per spec.
// GREASE = Generate Random Extensions And Sustain Extensibility (RFC 8701)
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// ClientHello holds the parsed fields from a TLS ClientHello message.
// These are exactly the fields used in the JA3 fingerprint.
type ClientHello struct {
	Version            uint16
	CipherSuites       []uint16
	Extensions         []uint16
	EllipticCurves     []uint16 // Extension 10 (supported_groups)
	EllipticCurvesPF   []uint8  // Extension 11 (ec_point_formats)
	RawBytes           []byte
	ServerName         string
}

// JA3Result holds the computed fingerprint and its components.
type JA3Result struct {
	Hash       string
	RawString  string
	Version    uint16
	Ciphers    []uint16
	Extensions []uint16
	Curves     []uint16
	PointFmts  []uint8
}

// Compute calculates the JA3 fingerprint from a parsed ClientHello.
//
// JA3 string format:
//   SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// Each field is a hyphen-separated list of decimal values.
// GREASE values are excluded. The final hash is MD5 of this string.
func Compute(hello *ClientHello) *JA3Result {
	// Filter GREASE from all fields
	ciphers := filterGREASEU16(hello.CipherSuites)
	extensions := filterGREASEU16(hello.Extensions)
	curves := filterGREASEU16(hello.EllipticCurves)

	// Build each segment
	versionStr := strconv.Itoa(int(hello.Version))
	cipherStr := joinUint16(ciphers, "-")
	extStr := joinUint16(extensions, "-")
	curveStr := joinUint16(curves, "-")
	pointStr := joinUint8(hello.EllipticCurvesPF, "-")

	raw := strings.Join([]string{
		versionStr,
		cipherStr,
		extStr,
		curveStr,
		pointStr,
	}, ",")

	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))

	return &JA3Result{
		Hash:       hash,
		RawString:  raw,
		Version:    hello.Version,
		Ciphers:    ciphers,
		Extensions: extensions,
		Curves:     curves,
		PointFmts:  hello.EllipticCurvesPF,
	}
}

// ComputeJA3S calculates the JA3S fingerprint from a ServerHello.
// JA3S = SSLVersion,Cipher,Extensions
// Used in server mode to fingerprint server responses.
type ServerHello struct {
	Version    uint16
	CipherSuite uint16
	Extensions []uint16
}

func ComputeJA3S(hello *ServerHello) *JA3Result {
	extensions := filterGREASEU16(hello.Extensions)

	raw := fmt.Sprintf("%d,%d,%s",
		hello.Version,
		hello.CipherSuite,
		joinUint16(extensions, "-"),
	)

	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))

	return &JA3Result{
		Hash:      hash,
		RawString: raw,
		Version:   hello.Version,
		Ciphers:   []uint16{hello.CipherSuite},
		Extensions: extensions,
	}
}

// --- Helpers ---

func filterGREASEU16(vals []uint16) []uint16 {
	result := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !greaseValues[v] {
			result = append(result, v)
		}
	}
	return result
}

func joinUint16(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

func joinUint8(vals []uint8, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

// CipherSuiteName returns a human-readable name for a cipher suite value.
func CipherSuiteName(id uint16) string {
	names := map[uint16]string{
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
		0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		0x0000: "TLS_NULL_WITH_NULL_NULL",
		0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", id)
}

// ExtensionName returns a human-readable name for a TLS extension type.
func ExtensionName(id uint16) string {
	names := map[uint16]string{
		0:  "server_name",
		1:  "max_fragment_length",
		5:  "status_request",
		10: "supported_groups",
		11: "ec_point_formats",
		13: "signature_algorithms",
		14: "use_srtp",
		15: "heartbeat",
		16: "application_layer_protocol_negotiation",
		17: "status_request_v2",
		18: "signed_certificate_timestamp",
		21: "padding",
		22: "encrypt_then_mac",
		23: "extended_master_secret",
		27: "compress_certificate",
		28: "record_size_limit",
		35: "session_ticket",
		41: "pre_shared_key",
		42: "early_data",
		43: "supported_versions",
		44: "cookie",
		45: "psk_key_exchange_modes",
		47: "certificate_authorities",
		48: "oid_filters",
		49: "post_handshake_auth",
		50: "signature_algorithms_cert",
		51: "key_share",
		65281: "renegotiation_info",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", id)
}

// CurveNames maps elliptic curve IDs to names.
var CurveNames = map[uint16]string{
	23:  "secp256r1 (P-256)",
	24:  "secp384r1 (P-384)",
	25:  "secp521r1 (P-521)",
	29:  "x25519",
	30:  "x448",
	256: "ffdhe2048",
	257: "ffdhe3072",
}

