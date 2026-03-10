package tls

import (
	"encoding/binary"
	"fmt"
)

// ParseClientHello parses raw bytes from a TLS record layer into a ClientHello struct.
//
// TLS Record structure:
//   Byte 0:     Content Type (0x16 = Handshake)
//   Bytes 1-2:  Legacy Record Version (e.g. 0x0301 = TLS 1.0)
//   Bytes 3-4:  Length
//   Byte 5:     Handshake Type (0x01 = ClientHello)
//   Bytes 6-8:  Handshake Length (3 bytes, big-endian)
//   Bytes 9-10: Client Version
//   Bytes 11-42: Random (32 bytes)
//   Byte 43:    Session ID Length
//   ...         Session ID
//   ...         Cipher Suites Length (2 bytes)
//   ...         Cipher Suites
//   ...         Compression Methods Length (1 byte)
//   ...         Compression Methods
//   ...         Extensions Length (2 bytes)
//   ...         Extensions
func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record header")
	}

	// Validate TLS record header
	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record (content type: 0x%02X)", data[0])
	}

	// Move past the 5-byte record header
	pos := 5

	if pos >= len(data) {
		return nil, fmt.Errorf("no handshake data after record header")
	}

	// Handshake type must be ClientHello (0x01)
	if data[pos] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello (handshake type: 0x%02X)", data[pos])
	}
	pos++

	// Skip 3-byte handshake length
	if pos+3 > len(data) {
		return nil, fmt.Errorf("truncated handshake length")
	}
	pos += 3

	hello := &ClientHello{}

	// Client Version (2 bytes)
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated client version")
	}
	hello.Version = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Random (32 bytes) — skip
	if pos+32 > len(data) {
		return nil, fmt.Errorf("truncated random")
	}
	pos += 32

	// Session ID Length (1 byte) + Session ID
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated session ID length")
	}
	sessionIDLen := int(data[pos])
	pos++
	if pos+sessionIDLen > len(data) {
		return nil, fmt.Errorf("truncated session ID")
	}
	pos += sessionIDLen

	// Cipher Suites Length (2 bytes)
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	// Cipher Suites (2 bytes each)
	if pos+cipherSuitesLen > len(data) {
		return nil, fmt.Errorf("truncated cipher suites")
	}
	hello.CipherSuites = make([]uint16, 0, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		hello.CipherSuites = append(hello.CipherSuites, cs)
	}
	pos += cipherSuitesLen

	// Compression Methods Length (1 byte) + Methods
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated compression methods length")
	}
	compressionLen := int(data[pos])
	pos++
	if pos+compressionLen > len(data) {
		return nil, fmt.Errorf("truncated compression methods")
	}
	pos += compressionLen

	// Extensions (optional — TLS 1.3 always has them, older may not)
	if pos+2 > len(data) {
		// No extensions — still valid, just less info
		hello.RawBytes = data
		return hello, nil
	}

	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+extensionsLen > len(data) {
		return nil, fmt.Errorf("truncated extensions block")
	}

	// Parse each extension
	extEnd := pos + extensionsLen
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extEnd {
			break
		}

		extData := data[pos : pos+extLen]
		hello.Extensions = append(hello.Extensions, extType)

		switch extType {
		case 0x0000: // server_name
			hello.ServerName = parseServerName(extData)

		case 0x000A: // supported_groups (elliptic curves)
			hello.EllipticCurves = parseSupportedGroups(extData)

		case 0x000B: // ec_point_formats
			hello.EllipticCurvesPF = parsePointFormats(extData)
		}

		pos += extLen
	}

	hello.RawBytes = data
	return hello, nil
}

// ParseServerHello parses a ServerHello message for JA3S computation.
func ParseServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short")
	}

	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record")
	}

	pos := 5

	if data[pos] != 0x02 {
		return nil, fmt.Errorf("not a ServerHello (type: 0x%02X)", data[pos])
	}
	pos++

	// Skip handshake length (3 bytes)
	pos += 3

	hello := &ServerHello{}

	// Server Version
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated server version")
	}
	hello.Version = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Random (32 bytes)
	pos += 32

	// Session ID
	if pos >= len(data) {
		return hello, nil
	}
	sessionIDLen := int(data[pos])
	pos++
	pos += sessionIDLen

	// Cipher Suite (2 bytes)
	if pos+2 > len(data) {
		return hello, nil
	}
	hello.CipherSuite = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Compression Method (1 byte)
	pos++

	// Extensions
	if pos+2 > len(data) {
		return hello, nil
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	extEnd := pos + extLen
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		thisExtLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		hello.Extensions = append(hello.Extensions, extType)
		pos += thisExtLen
	}

	return hello, nil
}

// --- Extension parsers ---

func parseServerName(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// Server Name List Length (2 bytes), then entries
	pos := 2
	for pos+3 <= len(data) {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if nameType == 0x00 && pos+nameLen <= len(data) { // host_name
			return string(data[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

func parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	groups := make([]uint16, 0, listLen/2)
	for i := 2; i+2 <= 2+listLen && i+2 <= len(data); i += 2 {
		groups = append(groups, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return groups
}

func parsePointFormats(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	formats := make([]uint8, 0, listLen)
	for i := 1; i <= listLen && i < len(data); i++ {
		formats = append(formats, data[i])
	}
	return formats
}
