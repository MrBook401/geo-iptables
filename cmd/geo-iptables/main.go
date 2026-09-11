// Command geo-iptables is the CLI entry point for the geo-iptables tool.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"geo-iptables/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
