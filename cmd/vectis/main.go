package main

import (
	"os"

	"github.com/Veltara-Works/vectis/internal/cli"
)

func main() {
	if err := cli.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
