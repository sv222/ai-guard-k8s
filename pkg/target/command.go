package target

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func CommandLine(c corev1.Container) []string {
	raw := make([]string, 0, len(c.Command)+len(c.Args))
	raw = append(raw, c.Command...)
	raw = append(raw, c.Args...)
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		if !strings.ContainsAny(a, " \t\r\n") {
			out = append(out, a)
			continue
		}
		for _, f := range strings.Fields(a) {
			if f = strings.Trim(f, "\"'"); f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}
