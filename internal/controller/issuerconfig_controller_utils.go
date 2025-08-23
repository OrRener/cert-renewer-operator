package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
)

func (r *IssuerConfigReconciler) UpdateObjectStatus(ctx context.Context, instance *certv1.IssuerConfig) error {
	err := r.Status().Update(ctx, instance)
	if err != nil {
		return err
	}
	return nil
}

func (r *IssuerConfigReconciler) FetchInstance(ctx context.Context, name string, namespace string) (*certv1.IssuerConfig, error) {
	instance := &certv1.IssuerConfig{}
	err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *IssuerConfigReconciler) updateSecret(ctx context.Context, instance *certv1.IssuerConfig) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: instance.Spec.AcmeSecret.SecretRef.Namespace,
			Name:      instance.Spec.AcmeSecret.SecretRef.Name,
		},
		Data: map[string][]byte{},
	}
	patch := client.MergeFrom(secret.DeepCopy())
	secret.Data["acmeMail"] = []byte(instance.Spec.Email)
	secret.Data["acmeHost"] = []byte(instance.Spec.AcmeHost)
	secret.Data["pdnsHost"] = []byte(instance.Spec.PdnsHost)
	secret.Labels = map[string]string{
		"cert.compute.io/issuer":  fmt.Sprintf("%s.%s", instance.Namespace, instance.Name),
		"cert.compute.io/managed": "true",
	}

	return r.Patch(ctx, secret, patch)
}

func (r *IssuerConfigReconciler) CreateCertStatus(status, message string) certv1.IssuerConfigStatus {
	return certv1.IssuerConfigStatus{
		Status:  status,
		Message: message,
	}
}

func (r *IssuerConfigReconciler) cleanup(ctx context.Context) error {

	selector, err := labels.NewRequirement("cert.compute.io/issuer", selection.Exists, nil)
	if err != nil {
		return fmt.Errorf("failed to create label selector for cleanup: %w", err)
	}

	secretList := &corev1.SecretList{}
	listOpts := []client.ListOption{
		client.MatchingLabelsSelector{Selector: labels.NewSelector().Add(*selector)},
	}

	if err := r.List(ctx, secretList, listOpts...); err != nil {
		return fmt.Errorf("failed to list secrets for cleanup: %w", err)
	}

	for _, secret := range secretList.Items {
		secretToUpdate := secret.DeepCopy()

		if secretToUpdate.Labels != nil {
			delete(secretToUpdate.Labels, "cert.compute.io/issuer")
		}
		if err := r.Client.Patch(ctx, secretToUpdate, client.MergeFrom(&secret)); err != nil {
			return fmt.Errorf("failed to remove label from secret %s: %w", secretToUpdate.Name, err)
		}
	}

	return nil
}
