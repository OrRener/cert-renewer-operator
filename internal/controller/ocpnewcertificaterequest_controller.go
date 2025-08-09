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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
)

// OCPNewCertificateRequestReconciler reconciles a OCPNewCertificateRequest object
type OCPNewCertificateRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpnewcertificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpnewcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpnewcertificaterequests/finalizers,verbs=update
func (r *OCPNewCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	var message string
	log := logf.FromContext(ctx)
	instance := &certv1.OCPNewCertificateRequest{}
	err := r.Get(ctx, client.ObjectKey{Name: req.Name, Namespace: req.Namespace}, instance)
	if err != nil {
		log.Error(err, "Failed to fetch OCPCertificateTracker")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info("Successfully fetched instance", "instance:", instance)

	var certInputs []certv1.TargetSecret
	for _, cert := range instance.Spec.Certificates {
		domains := cert.Domains
		certInputs = append(certInputs, certv1.TargetSecret{
			Name:    cert.Name,
			Dnses:   domains,
			GitPath: cert.GitPath,
		})
	}
	certCR := &certv1.OCPCertificateApplier{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name + "-applier",
			Namespace: "ocp-controller-cert-renewer",
		},
		Spec: certv1.OCPCertificateApplierSpec{
			CertificatesToCreate: certInputs,
			GitBranch:            "test-auto-create-certs",
		},
	}
	existing := &certv1.OCPCertificateApplier{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      certCR.Name,
		Namespace: certCR.Namespace,
	}, existing)

	if err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "Failed to fetch existing OCPCertificateApplier", "instance:", instance)
		message = err.Error()
	} else if apierrors.IsNotFound(err) {
		err = r.Create(ctx, certCR)
		if err != nil {
			log.Error(err, "Failed to create new OCPCertificateApplier", "instance:", instance)
			message = err.Error()
		}
	} else {
		existing.Spec = certCR.Spec
		if err := r.Update(ctx, existing); err != nil {
			log.Error(err, "Failed to update existing instance", "instance:", instance)
			message = err.Error()
		} else {
			message = "Successfully created OCPCertificateApplier, name:" + instance.Name + "-applier"
		}
	}
	instance.Status.Message = message
	err = r.Status().Update(ctx, instance)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update instance status:", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Suceessfully create cooresponding OCPCertificateApplier", "instance:", instance)
	return ctrl.Result{}, nil

}

// SetupWithManager sets up the controller with the Manager.
func (r *OCPNewCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.OCPNewCertificateRequest{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{})).
		Named("ocpnewcertificaterequest").
		Complete(r)
}
