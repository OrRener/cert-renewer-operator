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
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	"github.com/go-acme/lego/v4/lego"
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

	var statuses []certv1.CertificateRequestStatus
	acmeSetup := false
	var user *MyUser
	branch := "auto-create-certs"
	var legoClient *lego.Client

	log := logf.FromContext(ctx)
	instance, err := r.FetchInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		log.Error(err, "Failed to fetch OCPCertificateTracker")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	for _, cert := range instance.Spec.Certificates {
		status := r.ExtractCertificateStatusFromName(cert.Name, instance)
		switch status.Status {
		case "NonExistant", "Error":
			if !acmeSetup {
				privateKey, err := r.generatePrivateKey()
				if err != nil {
					log.Error(err, "Failed to generate private key", "instance:", instance)
					return ctrl.Result{}, err
				}
				user, legoClient, err = r.SetupACME(ctx, instance, "orrener2000or@gmail.com", privateKey)
				if err != nil {
					log.Error(err, "Failed to generate private key", "instance:", instance)
					return ctrl.Result{}, err
				}
				acmeSetup = true
			}
			SignedCeritificate, CertificateStatus, err := r.CreateNewCertificate(ctx, instance, cert, *user, legoClient)
			if err != nil {
				log.Error(err, "failed to sign certificate", "certificate:", cert.Name)
			} else {
				err = r.CreateSecret(ctx, SignedCeritificate, cert)
				if err != nil {
					log.Error(err, "failed to create secret for certificate", "cert", cert.Name)
					CertificateStatus.Status = "Error"
					CertificateStatus.Message = err.Error()
				}
			}
			statuses = append(statuses, CertificateStatus)
		case "Completed", "Signed":
			statuses = append(statuses, status)
		}
	}

	instance.Status.Certificates = statuses
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Signed (Encrypting keys)", "instance:", instance)
		return ctrl.Result{}, err
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(err, "Some certificates are in a failed state, cannot proceed", "instance", instance)
		return ctrl.Result{}, errors.New("some certificates failed")
	}

	log.Info("Successfully signed certs.", "instance:", instance)
	err = DeleteDirContents("repo")
	if err != nil {
		log.Error(err, "Failed to delete repo contents", "instance:", instance)
		return ctrl.Result{}, err
	}
	err = cloneRepo()
	if err != nil {
		log.Error(err, "Failed to clone repo ocpbm-cluster-config", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Successfully cloned git repo.", "instance:", instance)
	repo, wt, err := CheckoutBranch(branch)
	if err != nil {
		log.Error(err, "Failed to checkout ocpbm-cluster-config", "instance:", instance)
		return ctrl.Result{}, err
	}

	for _, certificate := range instance.Spec.Certificates {
		var cert SignedCeritifactes
		certSecret, exists, err := r.getSecret(ctx, certificate.Name)
		if err != nil {
			log.Error(err, "failed to fetch secret", "secret:", "signed-"+certificate.Name)
			return ctrl.Result{}, err
		}
		if !exists {
			statuses = []certv1.CertificateRequestStatus{}
			log.Error(errors.New("secret not found"), "secret not found", "secret:", "new-"+certificate.Name)
			status := r.CreateCertStatus(certificate.Name, "secret not found", "Error")
			statuses = append(statuses, status)
			continue
		}
		if certificate.GitPath == "" {
			cert = SignedCeritifactes{
				Name: certSecret.Labels["cert.compute.io/cert-name"],
				Cert: certSecret.Data["tls.crt"],
				Key:  certSecret.Data["tls.key"],
			}
		} else {
			cert = SignedCeritifactes{
				Name: certSecret.Labels["cert.compute.io/cert-name"],
				Cert: certSecret.Data["tls.crt"],
				Key:  certSecret.Data["tls.key"],
			}
			encryptedKey, err := encryptKey(cert.Key)
			if err != nil {
				log.Error(err, "failed to encrypt key for certificate", "cert:", cert.Name)
				status := r.CreateCertStatus(cert.Name, err.Error(), "Error")
				statuses = append(statuses, status)
				continue
			}
			WriteToFile(filepath.Join("/repo", certificate.GitPath, "tls.key.enc"), encryptedKey)
			WriteToFile(filepath.Join("/repo", certificate.GitPath, "tls.crt"), cert.Cert)
			statuses = append(statuses, r.CreateCertStatus(cert.Name, "Key successfully encrypted", "Signed"))
		}
	}
	instance.Status.Certificates = statuses
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Signed (Encrypting keys)", "instance:", instance)
		return ctrl.Result{}, err
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(err, "Some certificates are in a failed state, cannot proceed", "instance", instance)
		return ctrl.Result{}, errors.New("some certificates failed")
	}
	log.Info("Successfully encrypted keys.", "instance:", instance)
	err = commitAndPushChanges(wt, repo, branch)
	if err != nil {
		log.Error(err, "Failed to commit changes", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Successfully commited and pushed changes.", "instance:", instance)
	mr, err := createMergeRequest(branch)
	if err != nil {
		log.Error(err, "Failed to create MR", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Successfully create MR,", "URL:", mr)
	statuses = []certv1.CertificateRequestStatus{}
	for _, cert := range instance.Status.Certificates {
		status := certv1.CertificateRequestStatus{
			Name:            cert.Name,
			Status:          "Completed",
			Message:         "Certificate present in git PR",
			SecretName:      "new-" + cert.Name,
			SecretNamespace: "ocp-controller-cert-renewer",
		}
		statuses = append(statuses, status)
	}
	instance.Status.Certificates = statuses
	instance.Status.GitMR = mr
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Completed", "instance:", instance)
		return ctrl.Result{}, err
	}

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
