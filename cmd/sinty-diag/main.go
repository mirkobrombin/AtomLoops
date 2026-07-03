// Command sinty-diag collects a failure bundle and emits a compact, QR-ready
// report. On a failed boot or install (late-stage, root mounted): it writes the
// full bundle where the user can retrieve it (--out, on SINTYLOGS) and prints the
// compact "SINTY-FAIL v1" payload, auto-sized to fit one QR, for the splash to
// render. --qr also writes the payload to a file.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mirkobrombin/atomloops/internal/diag"
)

func main() {
	stage := flag.String("stage", "boot", "failure stage: boot | install")
	errLine := flag.String("error", "", "one-line error, if the caller knows it")
	out := flag.String("out", "/run/sintylogs/diag-full.log", "where to write the full bundle")
	qr := flag.String("qr", "", "also write the compact QR payload to this file")
	maxBytes := flag.Int("max-bytes", 1800, "QR payload budget in bytes (fits one ECC-M QR; dmesg tail shrinks to fit)")
	flag.Parse()

	b := diag.Collect(diag.DefaultConfig(*stage, *errLine), time.Now)

	if err := os.MkdirAll(dirOf(*out), 0o755); err == nil {
		_ = os.WriteFile(*out, b.Full(), 0o644)
	}
	_, payload, kept := b.CompactWithin(*maxBytes)
	if *qr != "" {
		_ = os.WriteFile(*qr, payload, 0o644)
	}
	fmt.Fprintf(os.Stderr, "id %s, full -> %s (%d bytes), qr payload %d bytes (dmesg lines kept: %d)\n",
		b.ID(), *out, len(b.Full()), len(payload), kept)
	os.Stdout.Write(payload)
	fmt.Println()
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
