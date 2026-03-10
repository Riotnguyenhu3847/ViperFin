package main

import (
	"fmt"
	"os"

	"viperfin/cmd"
)

const banner = `
 __   ___ ____  _____ ____  _____ ___ _   _ 
 \ \ / / |  _ \| ____|  _ \|  ___|_ _| \ | |
  \ V /| | |_) |  _| | |_) | |_   | ||  \| |
   | | | |  __/| |___|  _ <|  _|  | || |\  |
   |_| |_|_|   |_____|_| \_\_|   |___|_| \_|

  TLS Fingerprinting Tool — JA3/JA3S Implementation
  Coded by Egyan
`

func main() {
	fmt.Println(banner)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "client":
		cmd.RunClient(os.Args[2:])
	case "server":
		cmd.RunServer(os.Args[2:])
	case "lookup":
		cmd.RunLookup(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`Usage:
  viperfin client  <host:port> [--json] [--verbose]
      Connect to a TLS server, capture your own ClientHello,
      compute JA3 hash, and lookup against known signatures.

  viperfin server  [--port <port>] [--json] [--verbose]
      Listen for incoming TLS connections and fingerprint
      each connecting client (JA3 from their ClientHello).

  viperfin lookup  <ja3_hash>
      Lookup a known JA3 hash in the local signature database.

Examples:
  viperfin client google.com:443
  viperfin client example.com:443 --verbose
  viperfin server --port 4443
  viperfin lookup 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
`)
}
