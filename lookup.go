package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"viperfin/db"
	"viperfin/report"
)

// RunLookup handles the `viperfin lookup <hash>` subcommand.
func RunLookup(args []string) {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	listAll := fs.Bool("list", false, "List all known signatures in the database")
	filterThreat := fs.String("threat", "", "Filter by threat level: benign, info, suspicious, malicious")

	fs.Usage = func() {
		fmt.Println("Usage: viperfin lookup <ja3_hash> [flags]")
		fmt.Println()
		fmt.Println("Lookup a JA3 hash in the local signature database.")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  viperfin lookup 6bea65232d17d4884c427918d6c3abf0")
		fmt.Println("  viperfin lookup --list")
		fmt.Println("  viperfin lookup --list --threat malicious")
	}

	if err := fs.Parse(args); err != nil {
		fs.Usage()
		os.Exit(1)
	}

	if *listAll {
		printAllSignatures(*filterThreat)
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	hash := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	sig := db.Lookup(hash)
	report.PrintLookupResult(hash, sig)
}

func printAllSignatures(filterThreat string) {
	all := db.All()

	fmt.Printf("\n\033[1m\033[36m[ JA3 SIGNATURE DATABASE — %d entries ]\033[0m\n", len(all))
	fmt.Println(strings.Repeat("─", 80))

	counts := map[string]int{}
	for _, sig := range all {
		if filterThreat != "" && sig.ThreatLevel != filterThreat {
			continue
		}
		color := db.ThreatColor(sig.ThreatLevel)
		icon := db.ThreatIcon(sig.ThreatLevel)
		fmt.Printf("  %s%s %-12s\033[0m  %-34s  %s\n",
			color, icon, strings.ToUpper(sig.ThreatLevel),
			sig.Hash[:16]+"...",
			sig.Label,
		)
		counts[sig.ThreatLevel]++
	}

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("  \033[32m✓ Benign: %d\033[0m  \033[36mℹ Info: %d\033[0m  \033[33m⚠ Suspicious: %d\033[0m  \033[31m✗ Malicious: %d\033[0m\n\n",
		counts["benign"], counts["info"], counts["suspicious"], counts["malicious"])
}
