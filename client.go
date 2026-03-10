package cmd

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"viperfin/db"
	"viperfin/report"
	tlspkg "viperfin/tls"
)

// RunClient handles the `viperfin client <host:port>` subcommand.
func RunClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Output as JSON")
	verbose := fs.Bool("verbose", false, "Show cipher suites, extensions, and curves in detail")
	insecure := fs.Bool("insecure", false, "Skip TLS certificate verification")
	_ = insecure // used in future extension

	fs.Usage = func() {
		fmt.Println("Usage: viperfin client <host:port> [flags]")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  viperfin client google.com:443")
		fmt.Println("  viperfin client example.com:443 --verbose")
		fmt.Println("  viperfin client 10.0.0.1:8443 --insecure --json")
	}

	if err := fs.Parse(args); err != nil || fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)
	host, portStr, err := parseTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Target:  %s\n", target)
	fmt.Printf("[*] Database: %d known signatures loaded\n", db.Count())

	result, err := tlspkg.ConnectAndCapture(host, portStr, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var sig *db.Signature
	if result.ClientJA3 != nil {
		sig = db.Lookup(result.ClientJA3.Hash)
	}

	if *jsonOut {
		type jsonResult struct {
			Target     string `json:"target"`
			JA3Hash    string `json:"ja3_hash"`
			JA3Raw     string `json:"ja3_raw_string"`
			JA3SHash   string `json:"ja3s_hash,omitempty"`
			TLSVersion string `json:"tls_version_negotiated,omitempty"`
			CertCN     string `json:"cert_subject,omitempty"`
			Match      *db.Signature `json:"signature_match"`
		}
		out := jsonResult{Target: result.Target}
		if result.ClientJA3 != nil {
			out.JA3Hash = result.ClientJA3.Hash
			out.JA3Raw = result.ClientJA3.RawString
		}
		if result.ServerJA3S != nil {
			out.JA3SHash = result.ServerJA3S.Hash
		}
		if result.TLSVersion != 0 {
			out.TLSVersion = tlspkg.TLSVersionName(result.TLSVersion)
		}
		out.CertCN = result.CertSubject
		out.Match = sig
		report.PrintJSON(out)
		return
	}

	report.PrintClientResult(result, sig, *verbose)
}

// parseTarget splits a host:port string, defaulting port to 443.
func parseTarget(target string) (string, int, error) {
	// Handle bare hostname (no port)
	if !strings.Contains(target, ":") {
		return target, 443, nil
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target %q: %w", target, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}

	return host, port, nil
}
