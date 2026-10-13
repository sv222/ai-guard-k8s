package target

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type WorkloadTarget struct {
	Kind, Namespace, Name, Source string
	Labels                        map[string]string
	PodSpec                       corev1.PodSpec
}

// Containers returns the pod spec's containers (convenience alias).
func (w *WorkloadTarget) Containers() []corev1.Container { return w.PodSpec.Containers }

type NetworkPolicyEntry struct {
	Namespace   string
	PodSelector metav1.LabelSelector
}

type ServiceEntry struct {
	Namespace, Name, Type string
	Selector              map[string]string
	Ports                 []int32
}

type DirScan struct {
	Targets  []WorkloadTarget
	NetPols  []NetworkPolicyEntry
	Services []ServiceEntry
}

type anyDoc struct {
	Kind     string          `json:"kind"`
	Metadata json.RawMessage `json:"metadata"`
	Spec     json.RawMessage `json:"spec"`
}

type anyMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

// FromDir parses every .yaml/.yml/.json file under dir (multi-document safe)
// and extracts workloads, NetworkPolicies and Services.
func FromDir(dir string) (DirScan, error) {
	var out DirScan
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, doc := range splitDocs(data) {
			if err := consumeDoc(&out, doc, path); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		return nil
	})
	return out, err
}

func splitDocs(data []byte) [][]byte {
	var docs [][]byte
	cur := []byte{}
	rest := data
	for {
		i := indexSeparator(rest)
		if i < 0 {
			cur = append(cur, rest...)
			if len(trimSpace(cur)) > 0 {
				docs = append(docs, cur)
			}
			return docs
		}
		cur = append(cur, rest[:i]...)
		if len(trimSpace(cur)) > 0 {
			docs = append(docs, cur)
		}
		cur = []byte{}
		rest = rest[i+len(docSeparator):]
	}
}

const docSeparator = "\n---"

func indexSeparator(b []byte) int { return bytesIndex(b, []byte(docSeparator)) }

func consumeDoc(out *DirScan, doc []byte, source string) error {
	var ad anyDoc
	if err := yaml.Unmarshal(doc, &ad); err != nil {
		return nil // skip non-k8s docs (e.g. kustomization) silently
	}
	if ad.Kind == "" {
		return nil
	}
	var m anyMeta
	_ = json.Unmarshal(ad.Metadata, &m)
	switch ad.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		var obj appsv1.Deployment
		if err := strict(doc, &obj); err != nil {
			return err
		}
		out.Targets = append(out.Targets, WorkloadTarget{
			Kind: ad.Kind, Namespace: orDefault(m.Namespace, "default"), Name: m.Name,
			Labels: obj.Spec.Template.Labels, PodSpec: obj.Spec.Template.Spec, Source: source,
		})
	case "Job":
		var obj batchv1.Job
		if err := strict(doc, &obj); err != nil {
			return err
		}
		out.Targets = append(out.Targets, WorkloadTarget{
			Kind: "Job", Namespace: orDefault(m.Namespace, "default"), Name: m.Name,
			Labels: obj.Spec.Template.Labels, PodSpec: obj.Spec.Template.Spec, Source: source,
		})
	case "Pod":
		var obj corev1.Pod
		if err := strict(doc, &obj); err != nil {
			return err
		}
		out.Targets = append(out.Targets, WorkloadTarget{
			Kind: "Pod", Namespace: orDefault(m.Namespace, "default"), Name: m.Name,
			Labels: m.Labels, PodSpec: obj.Spec, Source: source,
		})
	case "NetworkPolicy":
		var obj netv1.NetworkPolicy
		if err := strict(doc, &obj); err != nil {
			return err
		}
		out.NetPols = append(out.NetPols, NetworkPolicyEntry{
			Namespace: orDefault(m.Namespace, "default"), PodSelector: obj.Spec.PodSelector,
		})
	case "Service":
		var obj corev1.Service
		if err := strict(doc, &obj); err != nil {
			return err
		}
		var ports []int32
		for _, p := range obj.Spec.Ports {
			ports = append(ports, p.Port)
		}
		out.Services = append(out.Services, ServiceEntry{
			Namespace: orDefault(m.Namespace, "default"), Name: m.Name,
			Type: string(obj.Spec.Type), Selector: obj.Spec.Selector, Ports: ports,
		})
	}
	return nil
}

func strict(doc []byte, obj interface{}) error {
	jsonBytes, err := yaml.YAMLToJSON(doc)
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonBytes, obj)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		last := b[len(b)-1]
		if last == ' ' || last == '\n' || last == '\t' || last == '\r' {
			b = b[:len(b)-1]
		} else {
			break
		}
	}
	return b
}

func bytesIndex(h, n []byte) int {
	for i := 0; i+len(n) <= len(h); i++ {
		match := true
		for j := range n {
			if h[i+j] != n[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
