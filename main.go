package main

import (
	"os"

	"github.com/aiguard/ai-guard-k8s/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
