/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
)

// IssuerConfigReconciler reconciles a IssuerConfig object
type IssuerConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cert.compute.io,resources=issuerconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=issuerconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=issuerconfigs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the IssuerConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *IssuerConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	instance, err := r.FetchInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		log.Error(err, "Failed to fetch OCPCertificateTracker")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if instance.GetDeletionTimestamp() != nil {
		if controllerutil.ContainsFinalizer(instance, finalizer) {
			log.Info("cleaning up secrets for deleted instance", "instance:", instance)
			err = r.cleanup(ctx)
			if err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(instance, finalizer)
			return ctrl.Result{}, r.Update(ctx, instance)
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(instance, finalizer) {
		controllerutil.AddFinalizer(instance, finalizer)
		err = r.Update(ctx, instance)
		if err != nil {
			log.Error(err, "failed to update object status", "instance:", instance)
			return ctrl.Result{}, err
		}
	}

	if instance.Spec.AcmeSecret.SecretRef.Namespace == "" {
		instance.Spec.AcmeSecret.SecretRef.Namespace = instance.Namespace
	}
	err = r.updateSecret(ctx, instance)
	if err != nil {
		log.Error(err, "failed to find secret", "instance:", instance.Name)
		instance.Status = r.CreateCertStatus("Error", err.Error())
		err = r.UpdateObjectStatus(ctx, instance)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	} else {
		log.Info("Successfully read info from issuerConfig", "instance:", instance)
	}
	instance.Status = r.CreateCertStatus("Success", "Info successfully read")
	err = r.UpdateObjectStatus(ctx, instance)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.IssuerConfig{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("issuerconfig").
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
				secret, ok := o.(*corev1.Secret)
				if !ok {
					return nil
				}

				ownerKey, ok := secret.Labels["cert.compute.io/issuer"]
				if !ok || ownerKey == "" {
					return nil
				}

				parts := strings.Split(ownerKey, ".")
				if len(parts) != 2 {
					return nil
				}
				ownerNamespace := parts[0]
				ownerName := parts[1]
				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      ownerName,
							Namespace: ownerNamespace,
						},
					},
				}
			}),
		).
		Complete(r)
}
