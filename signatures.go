package db

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed ja3_signatures.json
var signaturesJSON []byte

// Signature represents a known JA3 fingerprint entry.
type Signature struct {
	Hash        string `json:"hash"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	ThreatLevel string `json:"threat_level"`
	Notes       string `json:"notes"`
}

// ThreatLevel constants
const (
	ThreatBenign     = "benign"
	ThreatInfo       = "info"
	ThreatSuspicious = "suspicious"
	ThreatMalicious  = "malicious"
)

type sigDB struct {
	Signatures []Signature `json:"signatures"`
}

var db map[string]*Signature

func init() {
	var parsed sigDB
	if err := json.Unmarshal(signaturesJSON, &parsed); err != nil {
		panic(fmt.Sprintf("failed to load JA3 signature database: %v", err))
	}
	db = make(map[string]*Signature, len(parsed.Signatures))
	for i := range parsed.Signatures {
		db[strings.ToLower(parsed.Signatures[i].Hash)] = &parsed.Signatures[i]
	}
}

// Lookup queries the local database for a known JA3 hash.
// Returns nil if not found.
func Lookup(hash string) *Signature {
	return db[strings.ToLower(hash)]
}

// All returns all signatures in the database.
func All() []*Signature {
	result := make([]*Signature, 0, len(db))
	for _, sig := range db {
		result = append(result, sig)
	}
	return result
}

// Count returns the number of signatures in the database.
func Count() int {
	return len(db)
}

// ThreatColor returns an ANSI color code for a threat level string.
func ThreatColor(level string) string {
	switch level {
	case ThreatBenign:
		return "\033[32m" // green
	case ThreatInfo:
		return "\033[36m" // cyan
	case ThreatSuspicious:
		return "\033[33m" // yellow
	case ThreatMalicious:
		return "\033[31m" // red
	default:
		return "\033[37m" // white
	}
}

// ThreatIcon returns a visual indicator for terminal output.
func ThreatIcon(level string) string {
	switch level {
	case ThreatBenign:
		return "✓"
	case ThreatInfo:
		return "ℹ"
	case ThreatSuspicious:
		return "⚠"
	case ThreatMalicious:
		return "✗"
	default:
		return "?"
	}
}

const Reset = "\033[0m"
const Bold = "\033[1m"
