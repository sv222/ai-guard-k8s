package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
)

func PrintTable(w io.Writer, findings []checks.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tWORKLOAD\tTITLE\tEVIDENCE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s/%s/%s\t%s\t%s\n", f.ID, f.Severity,
			f.Kind, f.Namespace, f.Name, f.Title, f.Evidence)
	}
	return tw.Flush()
}

func PrintJSON(w io.Writer, findings []checks.Finding) error {
	if findings == nil {
		findings = []checks.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
