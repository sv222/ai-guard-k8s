package main

import (
	"os"

	"github.com/aiguard/ai-guard-k8s/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(2)
	}
}
