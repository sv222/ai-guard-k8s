package target

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// FromCluster loads workloads, NetworkPolicies and Services from a live cluster.
func FromCluster(kubeconfig, namespace string) (DirScan, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return DirScan{}, err
	}
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return DirScan{}, err
	}
	ctx := context.TODO()
	opt := metav1.ListOptions{}
	var out DirScan

	deps, err := cs.AppsV1().Deployments(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range deps.Items {
		out.Targets = append(out.Targets, WorkloadTarget{Kind: "Deployment",
			Namespace: o.Namespace, Name: o.Name, Labels: o.Spec.Template.Labels,
			PodSpec: o.Spec.Template.Spec, Source: "cluster"})
	}
	sts, err := cs.AppsV1().StatefulSets(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range sts.Items {
		out.Targets = append(out.Targets, WorkloadTarget{Kind: "StatefulSet",
			Namespace: o.Namespace, Name: o.Name, Labels: o.Spec.Template.Labels,
			PodSpec: o.Spec.Template.Spec, Source: "cluster"})
	}
	dss, err := cs.AppsV1().DaemonSets(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range dss.Items {
		out.Targets = append(out.Targets, WorkloadTarget{Kind: "DaemonSet",
			Namespace: o.Namespace, Name: o.Name, Labels: o.Spec.Template.Labels,
			PodSpec: o.Spec.Template.Spec, Source: "cluster"})
	}
	jobs, err := cs.BatchV1().Jobs(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range jobs.Items {
		out.Targets = append(out.Targets, WorkloadTarget{Kind: "Job",
			Namespace: o.Namespace, Name: o.Name, Labels: o.Spec.Template.Labels,
			PodSpec: o.Spec.Template.Spec, Source: "cluster"})
	}
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range pods.Items {
		out.Targets = append(out.Targets, WorkloadTarget{Kind: "Pod",
			Namespace: o.Namespace, Name: o.Name, Labels: o.Labels,
			PodSpec: o.Spec, Source: "cluster"})
	}
	nps, err := cs.NetworkingV1().NetworkPolicies(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range nps.Items {
		out.NetPols = append(out.NetPols, NetworkPolicyEntry{Namespace: o.Namespace, PodSelector: o.Spec.PodSelector})
	}
	svcs, err := cs.CoreV1().Services(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range svcs.Items {
		var ports []int32
		for _, p := range o.Spec.Ports {
			ports = append(ports, p.Port)
		}
		out.Services = append(out.Services, ServiceEntry{Namespace: o.Namespace, Name: o.Name,
			Type: string(o.Spec.Type), Selector: o.Spec.Selector, Ports: ports})
	}
	return out, nil
}
