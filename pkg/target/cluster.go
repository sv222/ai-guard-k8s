package target

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var controllerKinds = map[string]bool{
	"Deployment":            true,
	"ReplicaSet":            true,
	"StatefulSet":           true,
	"DaemonSet":             true,
	"Job":                   true,
	"CronJob":               true,
	"ReplicationController": true,
}

func IsManagedPod(meta metav1.ObjectMeta) bool {
	for _, ref := range meta.OwnerReferences {
		if ref.Controller != nil && *ref.Controller && controllerKinds[ref.Kind] {
			return true
		}
	}
	return false
}

func isControlledBy(meta metav1.ObjectMeta, kind string) bool {
	for _, ref := range meta.OwnerReferences {
		if ref.Controller != nil && *ref.Controller && ref.Kind == kind {
			return true
		}
	}
	return false
}

func FromCluster(ctx context.Context, kubeconfig, namespace string) (DirScan, error) {
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
	return FromClientset(ctx, cs, namespace)
}

func FromClientset(ctx context.Context, cs kubernetes.Interface, namespace string) (DirScan, error) {
	opt := metav1.ListOptions{}
	var out DirScan

	deps, err := cs.AppsV1().Deployments(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range deps.Items {
		out.Targets = append(out.Targets, fromTemplate("Deployment", o.ObjectMeta, o.Spec.Template, "cluster"))
	}
	sts, err := cs.AppsV1().StatefulSets(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range sts.Items {
		out.Targets = append(out.Targets, fromTemplate("StatefulSet", o.ObjectMeta, o.Spec.Template, "cluster"))
	}
	dss, err := cs.AppsV1().DaemonSets(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range dss.Items {
		out.Targets = append(out.Targets, fromTemplate("DaemonSet", o.ObjectMeta, o.Spec.Template, "cluster"))
	}
	rss, err := cs.AppsV1().ReplicaSets(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range rss.Items {
		if isControlledBy(o.ObjectMeta, "Deployment") || (o.Spec.Replicas != nil && *o.Spec.Replicas == 0) {
			continue
		}
		out.Targets = append(out.Targets, fromTemplate("ReplicaSet", o.ObjectMeta, o.Spec.Template, "cluster"))
	}
	rcs, err := cs.CoreV1().ReplicationControllers(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range rcs.Items {
		if o.Spec.Template == nil || (o.Spec.Replicas != nil && *o.Spec.Replicas == 0) {
			continue
		}
		out.Targets = append(out.Targets, fromTemplate("ReplicationController", o.ObjectMeta, *o.Spec.Template, "cluster"))
	}
	jobs, err := cs.BatchV1().Jobs(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range jobs.Items {
		if isControlledBy(o.ObjectMeta, "CronJob") {
			continue
		}
		out.Targets = append(out.Targets, fromTemplate("Job", o.ObjectMeta, o.Spec.Template, "cluster"))
	}
	crons, err := cs.BatchV1().CronJobs(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range crons.Items {
		out.Targets = append(out.Targets, fromTemplate("CronJob", o.ObjectMeta, o.Spec.JobTemplate.Spec.Template, "cluster"))
	}
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range pods.Items {
		if IsManagedPod(o.ObjectMeta) {
			continue
		}
		out.Targets = append(out.Targets, WorkloadTarget{
			Kind: "Pod", Namespace: o.Namespace, Name: o.Name,
			Labels: o.Labels, MetaLabels: o.Labels,
			Annotations: o.Annotations, MetaAnnotations: o.Annotations,
			PodSpec: o.Spec, Source: "cluster",
		})
	}
	nps, err := cs.NetworkingV1().NetworkPolicies(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range nps.Items {
		out.NetPols = append(out.NetPols, NetworkPolicyEntry{Namespace: o.Namespace, Name: o.Name, Spec: o.Spec})
	}
	svcs, err := cs.CoreV1().Services(namespace).List(ctx, opt)
	if err != nil {
		return out, err
	}
	for _, o := range svcs.Items {
		out.Services = append(out.Services, serviceEntry(o))
	}
	ings, err := cs.NetworkingV1().Ingresses(namespace).List(ctx, opt)
	switch {
	case apierrors.IsForbidden(err):
		out.Warnings = append(out.Warnings, "cannot list Ingresses: "+err.Error())
	case err != nil:
		return out, err
	default:
		for _, o := range ings.Items {
			out.Ingresses = append(out.Ingresses, ingressEntry(o))
		}
	}
	return out, nil
}
