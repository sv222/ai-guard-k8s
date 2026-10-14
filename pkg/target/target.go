package target

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
)

type WorkloadTarget struct {
	Kind, Namespace, Name, Source string
	Labels                        map[string]string
	MetaLabels                    map[string]string
	Annotations                   map[string]string
	MetaAnnotations               map[string]string
	PodSpec                       corev1.PodSpec
}

func (w WorkloadTarget) IsHelmTestHook() bool {
	for _, h := range strings.Split(w.MergedAnnotations()["helm.sh/hook"], ",") {
		if strings.HasPrefix(strings.TrimSpace(h), "test") {
			return true
		}
	}
	return false
}

func (w WorkloadTarget) Containers() []corev1.Container { return w.PodSpec.Containers }

func (w WorkloadTarget) AllContainers() []corev1.Container {
	out := make([]corev1.Container, 0, len(w.PodSpec.InitContainers)+len(w.PodSpec.Containers))
	out = append(out, w.PodSpec.InitContainers...)
	return append(out, w.PodSpec.Containers...)
}

func (w WorkloadTarget) MergedLabels() map[string]string {
	return merge(w.MetaLabels, w.Labels)
}

func (w WorkloadTarget) MergedAnnotations() map[string]string {
	return merge(w.MetaAnnotations, w.Annotations)
}

func merge(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

type NetworkPolicyEntry struct {
	Namespace string
	Name      string
	Spec      netv1.NetworkPolicySpec
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
	Warnings []string
}
