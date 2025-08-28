// Package main provides the entry point for the cryptkeeper CLI application.
package main

import (
	"os"

	"cryptkeeper/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}