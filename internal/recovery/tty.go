package recovery

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// TTY is the interactive text-mode recovery UI: the fallback that works with no
// graphics at all -- a plain but interactive console menu. It
// drives the same Core as the Cairo UI, so the two never diverge in behavior.
type TTY struct {
	core *Core
	in   *bufio.Scanner
	out  io.Writer
}

// NewTTY builds a TTY UI reading from in and writing to out (injectable for tests).
func NewTTY(core *Core, in io.Reader, out io.Writer) *TTY {
	return &TTY{core: core, in: bufio.NewScanner(in), out: out}
}

// RunTTY runs the interactive menu on the console until the operator quits/reboots.
func RunTTY(ctx context.Context, core *Core) error {
	return NewTTY(core, os.Stdin, os.Stdout).Run(ctx)
}

func (t *TTY) printf(format string, a ...any) { fmt.Fprintf(t.out, format, a...) }

func (t *TTY) prompt(label string) (string, bool) {
	t.printf("%s", label)
	if !t.in.Scan() {
		return "", false
	}
	return strings.TrimSpace(t.in.Text()), true
}

// Run drives the menu loop.
func (t *TTY) Run(ctx context.Context) error {
	for {
		t.printf("\n=== Sinty Recovery ===\n")
		t.printf("  1) Connetti al wifi\n")
		t.printf("  2) Reinstalla Sinty (scarica)\n")
		t.printf("  3) Ripara (torna all'ultima buona)\n")
		t.printf("  4) Stato\n")
		t.printf("  5) Riavvia\n")
		t.printf("  q) Esci\n")
		choice, ok := t.prompt("> ")
		if !ok {
			return nil
		}
		switch choice {
		case "1":
			t.doWifi(ctx)
		case "2":
			t.doReinstall(ctx)
		case "3":
			t.doRepair()
		case "4":
			t.doStatus()
		case "5":
			t.printf("Riavvio...\n")
			return reboot()
		case "q", "Q":
			return nil
		default:
			t.printf("Scelta non valida.\n")
		}
	}
}

func (t *TTY) doWifi(ctx context.Context) {
	t.printf("Scansione reti...\n")
	nets, err := t.core.Scan(ctx)
	if err != nil {
		t.printf("Scan fallito: %v\n", err)
		return
	}
	if len(nets) == 0 {
		t.printf("Nessuna rete trovata.\n")
		return
	}
	for i, n := range nets {
		lock := " "
		if n.Secure {
			lock = "*"
		}
		t.printf("  %2d) [%s] %-32s %d dBm\n", i+1, lock, n.SSID, n.Signal)
	}
	sel, ok := t.prompt("Rete (numero)> ")
	if !ok {
		return
	}
	idx, err := strconv.Atoi(sel)
	if err != nil || idx < 1 || idx > len(nets) {
		t.printf("Selezione non valida.\n")
		return
	}
	n := nets[idx-1]
	psk := ""
	if n.Secure {
		psk, _ = t.prompt("Password> ")
	}
	t.printf("Connessione a %q...\n", n.SSID)
	if err := t.core.Connect(ctx, n.SSID, psk); err != nil {
		t.printf("Connessione fallita: %v\n", err)
		return
	}
	t.printf("Connesso.\n")
}

func (t *TTY) doReinstall(ctx context.Context) {
	c, ok := t.prompt("Scaricare e reinstallare una Sinty fresca? Serve la rete. [s/N]> ")
	if !ok || strings.ToLower(c) != "s" {
		return
	}
	t.printf("Scarico e verifico l'immagine firmata...\n")
	msg, err := t.core.Reinstall(ctx)
	if err != nil {
		t.printf("Reinstall fallita: %v\n", err)
		return
	}
	t.printf("%s\nRiavvia per bootare l'immagine nuova.\n", msg)
}

func (t *TTY) doRepair() {
	msg, err := t.core.Repair()
	if err != nil {
		t.printf("Ripara: %v\n", err)
		return
	}
	t.printf("%s\n", msg)
}

func (t *TTY) doStatus() {
	s, err := t.core.Status()
	if err != nil {
		t.printf("Stato: %v\n", err)
		return
	}
	t.printf("current=%s pending=%s rollback=%s last_known_good=%s\n",
		s.Current, s.Pending, s.Rollback, s.LastKnownGood)
	t.printf("boot_attempts=%d recovery=%s kernelcache=%d security=%d\n",
		s.BootAttempts, s.Recovery, s.Kernelcache, s.SecurityLevel)
}

func reboot() error { return exec.Command("reboot").Run() }
