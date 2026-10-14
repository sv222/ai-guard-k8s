package target

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestFromDirExtractsWorkload(t *testing.T) {
	ds, err := FromDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(ds.Targets))
	}
	w := ds.Targets[0]
	if w.Kind != "Deployment" || w.Namespace != "llm" || w.Name != "vllm-openai" {
		t.Errorf("workload identity = %s/%s/%s", w.Kind, w.Namespace, w.Name)
	}
	if w.Containers()[0].Image != "vllm/vllm-openai:v0.6.0" {
		t.Errorf("image = %s", w.Containers()[0].Image)
	}
	if w.MetaLabels["app"] != "vllm" || w.Labels["app"] != "vllm" {
		t.Errorf("labels meta=%v template=%v", w.MetaLabels, w.Labels)
	}
	if len(ds.NetPols) != 1 || ds.NetPols[0].Spec.PodSelector.MatchLabels != nil {
		t.Errorf("expected one netpol with empty podSelector, got %+v", ds.NetPols)
	}
	if len(ds.Services) != 1 || ds.Services[0].Type != "LoadBalancer" {
		t.Errorf("services = %+v", ds.Services)
	}
	if len(ds.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", ds.Warnings)
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFromDirMultiDocWarningsAndKinds(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("testdata/multidoc.yaml.txt")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "multi.yaml", string(data))
	ds, err := FromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(ds.Targets))
	}
	sts := ds.Targets[0]
	if sts.Kind != "StatefulSet" || sts.Namespace != "default" || sts.MetaLabels["ai.infra.guard/enabled"] != "true" {
		t.Errorf("statefulset target = %+v", sts)
	}
	if len(sts.AllContainers()) != 2 || sts.AllContainers()[0].Name != "init" {
		t.Errorf("AllContainers = %+v", sts.AllContainers())
	}
	if sts.MergedLabels()["app"] != "ollama" || sts.MergedAnnotations()["a"] != "b" {
		t.Errorf("merged metadata wrong: %v %v", sts.MergedLabels(), sts.MergedAnnotations())
	}
	if ds.Targets[1].Kind != "Pod" || ds.Targets[1].Name != "solo" {
		t.Errorf("pod target = %+v", ds.Targets[1])
	}
	if len(ds.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly 1 (ConfigMap must be skipped quietly)", ds.Warnings)
	}
	if !strings.Contains(ds.Warnings[0], "multi.yaml") || !strings.Contains(ds.Warnings[0], "document 3") {
		t.Errorf("warning lacks file/doc: %s", ds.Warnings[0])
	}
}

func TestFromDirJSONAndList(t *testing.T) {
	dir := t.TempDir()
	list := `{"apiVersion":"v1","kind":"List","items":[` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"a","namespace":"x"},"spec":{"template":{"spec":{"containers":[{"name":"c","image":"vllm/vllm"}]}}}},` +
		`{"apiVersion":"v1","kind":"Service","metadata":{"name":"s","namespace":"x"},"spec":{"type":"NodePort","selector":{"app":"a"},"ports":[{"port":80}]}}]}`
	writeFile(t, dir, "list.json", list)
	writeFile(t, dir, "notes.txt", "kind: Pod")
	ds, err := FromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 || len(ds.Services) != 1 || ds.Services[0].Type != "NodePort" {
		t.Errorf("targets=%d services=%+v", len(ds.Targets), ds.Services)
	}
}

func TestFromDirTypeErrorWarns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  replicas: many\n")
	ds, err := FromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 0 || len(ds.Warnings) != 1 || !strings.Contains(ds.Warnings[0], "bad.yaml") {
		t.Errorf("targets=%d warnings=%v", len(ds.Targets), ds.Warnings)
	}
}

func TestFromDirMissingPath(t *testing.T) {
	if _, err := FromDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error for missing path")
	}
}

func TestFromDirSingleFile(t *testing.T) {
	ds, err := FromDir("testdata/vllm-deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 {
		t.Errorf("targets = %d", len(ds.Targets))
	}
}

func TestWorkloadHelpers(t *testing.T) {
	w := WorkloadTarget{
		MetaLabels: map[string]string{"a": "meta", "b": "meta"},
		Labels:     map[string]string{"a": "tpl"},
		PodSpec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "i"}},
			Containers:     []corev1.Container{{Name: "c"}},
		},
	}
	m := w.MergedLabels()
	if m["a"] != "tpl" || m["b"] != "meta" {
		t.Errorf("merged = %v", m)
	}
	if len(w.Containers()) != 1 || len(w.AllContainers()) != 2 {
		t.Error("container helpers wrong")
	}
}

func TestIsManagedPod(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name string
		meta metav1.ObjectMeta
		want bool
	}{
		{"standalone", metav1.ObjectMeta{}, false},
		{"replicaset", metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Controller: &yes}}}, true},
		{"job", metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Controller: &yes}}}, true},
		{"non-controller ref", metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Controller: &no}}}, false},
		{"custom controller", metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Kind: "RayCluster", Controller: &yes}}}, false},
	}
	for _, tt := range tests {
		if got := IsManagedPod(tt.meta); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestFromClientsetSkipsManagedPods(t *testing.T) {
	yes := true
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "vllm", Namespace: "llm", Labels: map[string]string{"ai.infra.guard/enabled": "true"}},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "vllm"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "vllm/vllm"}}},
			}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "vllm-abc-123", Namespace: "llm",
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "vllm-abc", Controller: &yes}}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "vllm/vllm"}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "solo", Namespace: "llm", Labels: map[string]string{"app": "solo"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "ollama/ollama"}}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "llm"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "vllm"}, Ports: []corev1.ServicePort{{Port: 80}}},
		},
	)
	ds, err := FromClientset(context.Background(), cs, "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, w := range ds.Targets {
		names = append(names, w.Kind+"/"+w.Name)
	}
	if len(ds.Targets) != 2 || names[0] != "Deployment/vllm" || names[1] != "Pod/solo" {
		t.Errorf("targets = %v", names)
	}
	if ds.Targets[0].MetaLabels["ai.infra.guard/enabled"] != "true" || ds.Targets[0].Labels["app"] != "vllm" {
		t.Errorf("deployment labels not captured: %+v", ds.Targets[0])
	}
	if len(ds.Services) != 1 || ds.Services[0].Type != "LoadBalancer" {
		t.Errorf("services = %+v", ds.Services)
	}
}

func TestFromClusterWithoutKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	if _, err := FromCluster(context.Background(), "", ""); err == nil {
		t.Error("expected error without a usable kubeconfig")
	}
	if _, err := FromCluster(context.Background(), filepath.Join(t.TempDir(), "explicit-missing"), ""); err == nil {
		t.Error("expected error for missing explicit kubeconfig")
	}
}

func TestFromDirCronJob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cron.yaml", `apiVersion: batch/v1
kind: CronJob
metadata:
  name: vllm-batch
  namespace: llm
  labels:
    ai.infra.guard/enabled: "true"
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: vllm-batch
        spec:
          restartPolicy: Never
          containers:
            - name: c
              image: vllm/vllm-openai:v0.6.0
`)
	ds, err := FromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(ds.Targets))
	}
	w := ds.Targets[0]
	if w.Kind != "CronJob" || w.Namespace != "llm" || w.Name != "vllm-batch" {
		t.Errorf("identity = %s/%s/%s", w.Kind, w.Namespace, w.Name)
	}
	if w.Labels["app"] != "vllm-batch" || w.MetaLabels["ai.infra.guard/enabled"] != "true" {
		t.Errorf("labels template=%v meta=%v", w.Labels, w.MetaLabels)
	}
	if len(w.Containers()) != 1 || w.Containers()[0].Image != "vllm/vllm-openai:v0.6.0" {
		t.Errorf("containers = %+v", w.Containers())
	}
}

func TestFromClientsetCronJob(t *testing.T) {
	yes := true
	podSpec := corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "ollama/ollama"}}}
	cs := fake.NewSimpleClientset(
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "ollama-batch", Namespace: "llm"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "ollama"}},
					Spec:       podSpec,
				},
			}}},
		},
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "ollama-batch-29865441", Namespace: "llm",
				OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "ollama-batch", Controller: &yes}}},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec}},
		},
	)
	ds, err := FromClientset(context.Background(), cs, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 || ds.Targets[0].Kind != "CronJob" || ds.Targets[0].Name != "ollama-batch" ||
		ds.Targets[0].Labels["app"] != "ollama" {
		t.Errorf("targets = %+v", ds.Targets)
	}
}

func TestFromDirIngress(t *testing.T) {
	dir := t.TempDir()
	manifest := `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: llm
  annotations:
    nginx.ingress.kubernetes.io/auth-url: https://auth/check
spec:
  defaultBackend:
    service:
      name: fallback
      port:
        number: 80
  rules:
    - host: a.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: svc
                port:
                  number: 80
          - path: /again
            pathType: Prefix
            backend:
              service:
                name: svc
                port:
                  number: 80
    - host: b.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "i.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	ds, err := FromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Ingresses) != 1 {
		t.Fatalf("ingresses = %+v", ds.Ingresses)
	}
	got := ds.Ingresses[0]
	if got.Namespace != "llm" || got.Name != "web" || len(got.Services) != 2 || got.Services[0] != "fallback" || got.Services[1] != "svc" ||
		got.Annotations["nginx.ingress.kubernetes.io/auth-url"] == "" {
		t.Errorf("ingress = %+v", got)
	}
}

func TestFromClientsetIngress(t *testing.T) {
	pt := netv1.PathTypePrefix
	cs := fake.NewSimpleClientset(&netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "llm"},
		Spec: netv1.IngressSpec{Rules: []netv1.IngressRule{{IngressRuleValue: netv1.IngressRuleValue{HTTP: &netv1.HTTPIngressRuleValue{
			Paths: []netv1.HTTPIngressPath{{Path: "/", PathType: &pt, Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{Name: "svc"}}}},
		}}}}},
	})
	ds, err := FromClientset(context.Background(), cs, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Ingresses) != 1 || ds.Ingresses[0].Services[0] != "svc" {
		t.Errorf("ingresses = %+v", ds.Ingresses)
	}
}

func TestFromClientsetIngressForbiddenIsAWarning(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "ingresses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "", errors.New("denied"))
	})
	ds, err := FromClientset(context.Background(), cs, "")
	if err != nil {
		t.Fatalf("forbidden Ingress list must not fail the scan: %v", err)
	}
	if len(ds.Warnings) != 1 || !strings.Contains(ds.Warnings[0], "Ingresses") {
		t.Errorf("warnings = %v", ds.Warnings)
	}
}
