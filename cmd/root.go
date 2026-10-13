package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var Version = "dev"

const (
	ExitOK       = 0
	ExitFindings = 1
	ExitFailure  = 2
)

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

func NewRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "ai-guard",
		Short:         "Audit and harden AI inference workloads on Kubernetes (infrastructure layer, not prompts)",
		Version:       Version,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	var kubeconfig string
	root.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig path (defaults to KUBECONFIG)")
	root.AddCommand(newScanCmd(&kubeconfig), newEnforceCmd(&kubeconfig))
	return root
}

func Run(args []string, stdout, stderr io.Writer) int {
	root := NewRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintln(stderr, "Error:", ee.Err)
		}
		return ee.Code
	}
	fmt.Fprintln(stderr, "Error:", err)
	return ExitFailure
}

func Execute() int {
	return Run(os.Args[1:], os.Stdout, os.Stderr)
}

func runtimeError(err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Code: ExitFailure, Err: err}
}
