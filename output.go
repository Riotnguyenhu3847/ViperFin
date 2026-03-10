package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tlspkg "viperfin/tls"
	"viperfin/db"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	cyan   = "\033[36m"
	white  = "\033[37m"
	blue   = "\033[34m"
)

func separator(char string, width int) string {
	return strings.Repeat(char, width)
}

// PrintClientResult prints a full formatted report for client mode.
func PrintClientResult(result *tlspkg.CaptureResult, sig *db.Signature, verbose bool) {
	fmt.Println()
	fmt.Printf("%s%s[ CLIENT FINGERPRINT REPORT ]%s\n", bold, cyan, reset)
	fmt.Println(separator("─", 60))

	// Target info
	fmt.Printf("  %sTarget:%s     %s\n", bold, reset, result.Target)
	fmt.Printf("  %sSNI:%s        %s\n", bold, reset, result.ServerName)

	// TLS version negotiated
	if result.TLSVersion != 0 {
		fmt.Printf("  %sTLS Version:%s %s\n", bold, reset,
			tlspkg.TLSVersionName(result.TLSVersion))
	}

	// Server cert info
	if result.CertSubject != "" {
		fmt.Printf("  %sCert Subject:%s%s\n", bold, reset, result.CertSubject)
		fmt.Printf("  %sCert Issuer:%s %s\n", bold, reset, result.CertIssuer)
		expiry := result.CertExpiry
		daysLeft := int(time.Until(expiry).Hours() / 24)
		expiryColor := green
		if daysLeft < 30 {
			expiryColor = yellow
		}
		if daysLeft < 7 {
			expiryColor = red
		}
		fmt.Printf("  %sCert Expiry:%s %s%s (%d days)%s\n",
			bold, reset, expiryColor, expiry.Format("2006-01-02"), daysLeft, reset)
	}

	fmt.Println()
	fmt.Println(separator("─", 60))
	fmt.Printf("%s%s[ JA3 FINGERPRINT ]%s\n", bold, blue, reset)
	fmt.Println(separator("─", 60))

	if result.ClientJA3 != nil {
		ja3 := result.ClientJA3
		fmt.Printf("  %sJA3 Hash:%s    %s%s%s\n", bold, reset, bold, ja3.Hash, reset)
		fmt.Printf("  %sRaw String:%s  %s%s%s\n", bold, reset, dim, truncate(ja3.RawString, 80), reset)

		// Version component
		fmt.Printf("\n  %sTLS Version (ClientHello):%s %s (0x%04X)\n",
			bold, reset, tlspkg.TLSVersionName(ja3.Version), ja3.Version)

		if verbose {
			// Cipher suites
			fmt.Printf("\n  %sCipher Suites (%d):%s\n", bold, len(ja3.Ciphers), reset)
			for _, c := range ja3.Ciphers {
				fmt.Printf("    0x%04X  %s\n", c, tlspkg.CipherSuiteName(c))
			}

			// Extensions
			fmt.Printf("\n  %sExtensions (%d):%s\n", bold, len(ja3.Extensions), reset)
			for _, e := range ja3.Extensions {
				fmt.Printf("    %-5d  %s\n", e, tlspkg.ExtensionName(e))
			}

			// Elliptic curves
			if len(ja3.Curves) > 0 {
				fmt.Printf("\n  %sElliptic Curves (%d):%s\n", bold, len(ja3.Curves), reset)
				for _, c := range ja3.Curves {
					name := tlspkg.CurveNames[c]
					if name == "" {
						name = fmt.Sprintf("unknown(%d)", c)
					}
					fmt.Printf("    %-5d  %s\n", c, name)
				}
			}
		}
	} else {
		fmt.Printf("  %s[!] Could not compute JA3 (ClientHello capture failed)%s\n", yellow, reset)
	}

	// JA3S if available
	if result.ServerJA3S != nil {
		fmt.Println()
		fmt.Println(separator("─", 60))
		fmt.Printf("%s%s[ JA3S FINGERPRINT (Server) ]%s\n", bold, blue, reset)
		fmt.Println(separator("─", 60))
		fmt.Printf("  %sJA3S Hash:%s   %s%s%s\n", bold, reset, bold, result.ServerJA3S.Hash, reset)
		fmt.Printf("  %sRaw String:%s  %s%s%s\n", bold, reset, dim, truncate(result.ServerJA3S.RawString, 80), reset)
	}

	// Threat intel lookup
	fmt.Println()
	fmt.Println(separator("─", 60))
	fmt.Printf("%s%s[ THREAT INTELLIGENCE ]%s\n", bold, blue, reset)
	fmt.Println(separator("─", 60))

	if sig != nil {
		color := db.ThreatColor(sig.ThreatLevel)
		icon := db.ThreatIcon(sig.ThreatLevel)
		fmt.Printf("  %sMatch Found:%s\n", bold, reset)
		fmt.Printf("    %s%s %s [%s]%s\n", color, icon, sig.Label, strings.ToUpper(sig.ThreatLevel), reset)
		fmt.Printf("    Category: %s\n", sig.Category)
		fmt.Printf("    Notes:    %s\n", sig.Notes)
	} else {
		fmt.Printf("  %s[?] Hash not found in local signature database%s\n", dim, reset)
		fmt.Printf("  %sTip: Check https://ja3er.com/search/%s for community data%s\n",
			dim, result.ClientJA3.Hash, reset)
	}

	fmt.Println(separator("─", 60))
	fmt.Println()
}

// PrintServerEvent prints a single client fingerprint event in server mode.
func PrintServerEvent(conn *tlspkg.ClientConnection, sig *db.Signature) {
	ts := conn.Timestamp.Format("15:04:05")

	if conn.Error != nil {
		fmt.Printf("[%s] %s%-20s%s  ERROR: %v\n",
			ts, red, conn.RemoteAddr, reset, conn.Error)
		return
	}

	if conn.JA3 == nil {
		fmt.Printf("[%s] %s%-20s%s  (no JA3 computed)\n", ts, dim, conn.RemoteAddr, reset)
		return
	}

	threatColor := dim
	threatLabel := "UNKNOWN"
	icon := "?"

	if sig != nil {
		threatColor = db.ThreatColor(sig.ThreatLevel)
		threatLabel = strings.ToUpper(sig.ThreatLevel)
		icon = db.ThreatIcon(sig.ThreatLevel)
	}

	sni := ""
	if conn.ClientHello != nil && conn.ClientHello.ServerName != "" {
		sni = fmt.Sprintf("  SNI: %s", conn.ClientHello.ServerName)
	}

	label := "UNRECOGNIZED"
	if sig != nil {
		label = sig.Label
	}

	fmt.Printf("[%s] %-22s  %s%s %s%s  JA3: %s%s\n",
		ts,
		conn.RemoteAddr,
		threatColor, icon, threatLabel, reset,
		bold, conn.JA3.Hash,
	)
	fmt.Printf("         └─ %s%s%s%s\n", dim, label, sni, reset)
}

// PrintLookupResult displays a signature lookup result.
func PrintLookupResult(hash string, sig *db.Signature) {
	fmt.Println()
	fmt.Printf("%s%s[ JA3 LOOKUP ]%s\n", bold, cyan, reset)
	fmt.Println(separator("─", 50))
	fmt.Printf("  Hash: %s%s%s\n\n", bold, hash, reset)

	if sig == nil {
		fmt.Printf("  %s[?] Not found in local database (%d signatures)%s\n", yellow, db.Count(), reset)
		fmt.Printf("  %sTip: Submit to https://ja3er.com for community lookup%s\n", dim, reset)
	} else {
		color := db.ThreatColor(sig.ThreatLevel)
		icon := db.ThreatIcon(sig.ThreatLevel)
		fmt.Printf("  %sMatch:%s      %s%s %s%s\n", bold, reset, color, icon, sig.Label, reset)
		fmt.Printf("  %sThreat:%s     %s%s%s\n", bold, reset, color, strings.ToUpper(sig.ThreatLevel), reset)
		fmt.Printf("  %sCategory:%s   %s\n", bold, reset, sig.Category)
		fmt.Printf("  %sNotes:%s      %s\n", bold, reset, sig.Notes)
	}
	fmt.Println(separator("─", 50))
	fmt.Println()
}

// PrintJSON outputs a result as pretty-printed JSON.
func PrintJSON(v interface{}) {
	enc, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(enc))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
