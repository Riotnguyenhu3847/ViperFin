package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"viperfin/db"
	"viperfin/report"
	tlspkg "viperfin/tls"
)

// RunServer handles the `viperfin server` subcommand.
func RunServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 4443, "Port to listen on")
	jsonOut := fs.Bool("json", false, "Output events as JSON lines")
	verbose := fs.Bool("verbose", false, "Show full cipher suite details per connection")

	fs.Usage = func() {
		fmt.Println("Usage: viperfin server [flags]")
		fmt.Println()
		fmt.Println("Listens for TLS connections and fingerprints each client.")
		fmt.Println("Uses an auto-generated self-signed certificate (no setup needed).")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  viperfin server --port 4443")
		fmt.Println("  viperfin server --port 8443 --json")
		fmt.Println()
		fmt.Println("Then connect a client to trigger fingerprinting:")
		fmt.Println("  curl -k https://localhost:4443")
		fmt.Println("  python -c \"import urllib.request; urllib.request.urlopen('https://localhost:4443')\"")
	}

	if err := fs.Parse(args); err != nil {
		fs.Usage()
		os.Exit(1)
	}

	fmt.Printf("[*] Starting JA3 fingerprinting server on port %d\n", *port)
	fmt.Printf("[*] Database: %d known signatures loaded\n", db.Count())
	fmt.Printf("[*] Using auto-generated self-signed certificate\n")
	fmt.Printf("[*] Press Ctrl+C to stop\n")
	fmt.Println()

	results, stopCh, err := tlspkg.ServerMode(*port, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

	// Handle Ctrl+C gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Print column headers
	if !*jsonOut {
		fmt.Printf("%-10s  %-22s  %-12s  %-34s  %s\n",
			"TIME", "REMOTE ADDR", "THREAT", "JA3 HASH", "IDENTIFIED AS")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────")
	}

	stats := struct {
		total      int
		benign     int
		suspicious int
		malicious  int
		unknown    int
	}{}

	for {
		select {
		case <-sigCh:
			close(stopCh)
			fmt.Println()
			printServerStats(stats.total, stats.benign, stats.suspicious, stats.malicious, stats.unknown)
			return

		case conn, ok := <-results:
			if !ok {
				return
			}

			stats.total++
			var sig *db.Signature
			if conn.JA3 != nil {
				sig = db.Lookup(conn.JA3.Hash)
			}

			if sig != nil {
				switch sig.ThreatLevel {
				case db.ThreatBenign:
					stats.benign++
				case db.ThreatSuspicious:
					stats.suspicious++
				case db.ThreatMalicious:
					stats.malicious++
				default:
					stats.unknown++
				}
			} else {
				stats.unknown++
			}

			if *jsonOut {
				type jsonEvent struct {
					Time       string        `json:"timestamp"`
					RemoteAddr string        `json:"remote_addr"`
					JA3Hash    string        `json:"ja3_hash,omitempty"`
					JA3Raw     string        `json:"ja3_raw,omitempty"`
					SNI        string        `json:"sni,omitempty"`
					Match      *db.Signature `json:"signature_match"`
					Error      string        `json:"error,omitempty"`
				}
				event := jsonEvent{
					Time:       conn.Timestamp.Format(time.RFC3339),
					RemoteAddr: conn.RemoteAddr,
					Match:      sig,
				}
				if conn.JA3 != nil {
					event.JA3Hash = conn.JA3.Hash
					event.JA3Raw = conn.JA3.RawString
				}
				if conn.ClientHello != nil {
					event.SNI = conn.ClientHello.ServerName
				}
				if conn.Error != nil {
					event.Error = conn.Error.Error()
				}
				report.PrintJSON(event)
			} else {
				report.PrintServerEvent(conn, sig)
			}
		}
	}
}

func printServerStats(total, benign, suspicious, malicious, unknown int) {
	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Printf("  Session Summary: %d connections\n", total)
	fmt.Printf("  \033[32m✓ Benign:      %d\033[0m\n", benign)
	fmt.Printf("  \033[36mℹ Unknown:     %d\033[0m\n", unknown)
	fmt.Printf("  \033[33m⚠ Suspicious:  %d\033[0m\n", suspicious)
	fmt.Printf("  \033[31m✗ Malicious:   %d\033[0m\n", malicious)
	fmt.Println("─────────────────────────────────────────────────────────")
}
