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
	"errors"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
)

// OCPCertificateTrackerReconciler reconciles a OCPCertificateTracker object
type OCPCertificateTrackerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type CertInfo struct {
	Name      string
	Namespace string
	Secret    corev1.Secret
	CaCert    string `json:"caCert,omitempty"`
	Message   string
	Status    string `json:"status,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
	GitPath   string `json:"gitPath"`
}

type AboutToExpireCertificates struct {
	Name        string
	Namespace   string
	Application string
	GitPath     string
}

// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpnewcertificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpnewcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpnewcertificaterequests/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OCPCertificateTracker object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile

func (r *OCPCertificateTrackerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	statuses := []certv1.CertificatesStatusStruct{}
	aboutToExpire := []CertInfo{}

	instance, err := r.FetchInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		log.Error(err, "Failed to fetch OCPCertificateTracker")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	for _, cert := range instance.Spec.Certificates {
		status, secret, err := r.ReadSecret(cert, ctx, instance)
		if err != nil {
			log.Error(err, "Failed to fetch secret", "instance:", instance)
			statuses = append(statuses, status)
			continue
		}
		status, err = r.UpdateExpiryStatus(ctx, cert, instance, secret)
		if err != nil {
			log.Error(err, "Failed to analyze certificate", "certificate", cert.Name)
			statuses = append(statuses, status)
			continue
		}
		if status.Status == "About to expire" {
			aboutToExpire = append(aboutToExpire, CertInfo{
				Name:      status.Name,
				Namespace: status.Namespace,
				Secret:    *secret,
				CaCert:    status.CaCert,
				Message:   status.Message,
				Status:    status.Status,
				Expiry:    status.Expiry,
				GitPath:   cert.GitPath,
			})
		}
		statuses = append(statuses, status)
	}
	instance.Status.Certificates = statuses
	err = r.UpdateObjectStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status after check for expiration", "instance:", instance)
		return ctrl.Result{}, err
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(errors.New("some certificates failed"), "Some certificates are in a failed state, cannot proceed", "instance", instance)

		return ctrl.Result{}, errors.New("some certificates failed")
	}
	log.Info("Successfully updated certs.", "instance:", instance)
	if len(aboutToExpire) == 0 {
		log.Info("No certificates about to expire")
	} else {
		err = r.CreateOCPCertificateApplier(ctx, aboutToExpire, instance)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OCPCertificateTrackerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.OCPCertificateTracker{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{})).
		Named("ocpcertificatetracker").
		Complete(r)
}
