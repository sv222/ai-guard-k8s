package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	infoURI      = "https://github.com/sv222/ai-guard-k8s"
)

var ruleNames = map[string]string{
	"AIG-001": "No auth on the inference engine",
	"AIG-002": "Debug or insecure endpoint",
	"AIG-003": "Host namespaces",
	"AIG-004": "hostPath volume",
	"AIG-005": "Root, privileged or privilege escalation",
	"AIG-006": "Seccomp missing or Unconfined",
	"AIG-007": "No resource requests or limits",
	"AIG-008": "Unsafe model execution",
	"AIG-009": "No ingress isolation",
	"AIG-010": "Exposed by LoadBalancer, NodePort or Ingress",
	"AIG-011": "hostPort on an inference container",
	"AIG-012": "Dangerous Linux capabilities",
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

func sarifLevel(severity string) string {
	switch checks.SeverityRank(severity) {
	case 3:
		return "error"
	case 2:
		return "warning"
	}
	return "note"
}

func sarifURI(source string) string {
	if source == "" || source == "cluster" {
		return ""
	}
	if filepath.IsAbs(source) {
		p := filepath.ToSlash(source)
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return "file://" + escapeSegments(p)
	}
	return escapeSegments(path.Clean(filepath.ToSlash(source)))
}

func escapeSegments(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}

func fingerprint(f checks.Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{f.ID, f.Kind, f.Namespace, f.Name, f.Title, f.Evidence}, "\x00")))
	return hex.EncodeToString(h[:16])
}

func PrintSARIF(w io.Writer, findings []checks.Finding, version string) error {
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	order := make([]string, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Strings(order)
	index := map[string]int{}
	rules := make([]sarifRule, 0, len(order))
	for i, id := range order {
		index[id] = i
		name := ruleNames[id]
		if name == "" {
			name = id
		}
		rules = append(rules, sarifRule{
			ID: id, Name: name, ShortDescription: sarifText{name},
			HelpURI:    infoURI + "#what-it-checks",
			Properties: map[string]any{"tags": []string{"security", "kubernetes"}},
		})
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		obj := fmt.Sprintf("%s/%s/%s", f.Kind, f.Namespace, f.Name)
		msg := fmt.Sprintf("%s in %s: %s", f.Title, obj, f.Evidence)
		if f.Hint != "" {
			msg += ". Fix: " + f.Hint
		}
		loc := sarifLocation{LogicalLocations: []sarifLogical{{
			Name: f.Name, FullyQualifiedName: obj, Kind: "resource",
		}}}
		if uri := sarifURI(f.Source); uri != "" {
			loc.PhysicalLocation = &sarifPhysical{ArtifactLocation: sarifArtifact{uri}, Region: sarifRegion{max(f.Line, 1)}}
		}
		results = append(results, sarifResult{
			RuleID: f.ID, RuleIndex: index[f.ID], Level: sarifLevel(f.Severity),
			Message: sarifText{msg}, Locations: []sarifLocation{loc},
			PartialFingerprints: map[string]string{"aiGuardFinding/v1": fingerprint(f)},
		})
	}
	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{{
		Tool:    sarifTool{Driver: sarifDriver{Name: "ai-guard", Version: version, InformationURI: infoURI, Rules: rules}},
		Results: results,
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
