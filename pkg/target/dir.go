package target

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

type typeMeta struct {
	Kind  string            `json:"kind"`
	Items []json.RawMessage `json:"items"`
}

func FromDir(dir string) (DirScan, error) {
	var out DirScan
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		consumeFile(&out, data, path)
		return nil
	})
	return out, err
}

func consumeFile(out *DirScan, data []byte, path string) {
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for idx := 1; ; idx++ {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: %v", path, err))
			return
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		raw, err := yaml.YAMLToJSON(doc)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: document %d is not valid YAML: %v", path, idx, err))
			continue
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		if err := consumeObject(out, raw, path); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: document %d: %v", path, idx, err))
		}
	}
}

func consumeObject(out *DirScan, raw []byte, source string) error {
	var tm typeMeta
	if err := json.Unmarshal(raw, &tm); err != nil {
		return fmt.Errorf("not a Kubernetes object: %w", err)
	}
	if tm.Kind == "" {
		return nil
	}
	if strings.HasSuffix(tm.Kind, "List") && len(tm.Items) > 0 {
		for _, item := range tm.Items {
			if err := consumeObject(out, item, source); err != nil {
				return err
			}
		}
		return nil
	}
	switch tm.Kind {
	case "Deployment":
		var o appsv1.Deployment
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Targets = append(out.Targets, fromTemplate("Deployment", o.ObjectMeta, o.Spec.Template, source))
	case "StatefulSet":
		var o appsv1.StatefulSet
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Targets = append(out.Targets, fromTemplate("StatefulSet", o.ObjectMeta, o.Spec.Template, source))
	case "DaemonSet":
		var o appsv1.DaemonSet
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Targets = append(out.Targets, fromTemplate("DaemonSet", o.ObjectMeta, o.Spec.Template, source))
	case "Job":
		var o batchv1.Job
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Targets = append(out.Targets, fromTemplate("Job", o.ObjectMeta, o.Spec.Template, source))
	case "CronJob":
		var o batchv1.CronJob
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Targets = append(out.Targets, fromTemplate("CronJob", o.ObjectMeta, o.Spec.JobTemplate.Spec.Template, source))
	case "Pod":
		var o corev1.Pod
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Targets = append(out.Targets, WorkloadTarget{
			Kind: "Pod", Namespace: orDefault(o.Namespace, "default"), Name: o.Name,
			Labels: o.Labels, MetaLabels: o.Labels,
			Annotations: o.Annotations, MetaAnnotations: o.Annotations,
			PodSpec: o.Spec, Source: source,
		})
	case "NetworkPolicy":
		var o netv1.NetworkPolicy
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.NetPols = append(out.NetPols, NetworkPolicyEntry{
			Namespace: orDefault(o.Namespace, "default"), Name: o.Name, Spec: o.Spec,
		})
	case "Service":
		var o corev1.Service
		if err := decodeInto(raw, &o); err != nil {
			return err
		}
		out.Services = append(out.Services, serviceEntry(o))
	}
	return nil
}

func fromTemplate(kind string, meta metav1.ObjectMeta, tpl corev1.PodTemplateSpec, source string) WorkloadTarget {
	return WorkloadTarget{
		Kind: kind, Namespace: orDefault(meta.Namespace, "default"), Name: meta.Name,
		Labels: tpl.Labels, MetaLabels: meta.Labels,
		Annotations: tpl.Annotations, MetaAnnotations: meta.Annotations,
		PodSpec: tpl.Spec, Source: source,
	}
}

func serviceEntry(o corev1.Service) ServiceEntry {
	var ports []int32
	for _, p := range o.Spec.Ports {
		ports = append(ports, p.Port)
	}
	return ServiceEntry{
		Namespace: orDefault(o.Namespace, "default"), Name: o.Name,
		Type: string(o.Spec.Type), Selector: o.Spec.Selector, Ports: ports,
	}
}

func decodeInto(raw []byte, obj interface{}) error {
	return json.Unmarshal(raw, obj)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
