package controller

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	legolog "github.com/go-acme/lego/v4/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// OCPCertificateApplierReconciler reconciles a OCPCertificateApplier object
type OCPCertificateApplierReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type noopLogger struct{}

func (n *noopLogger) Fatal(args ...interface{})                 {}
func (n *noopLogger) Fatalf(format string, args ...interface{}) {}
func (n *noopLogger) Fatalln(args ...interface{})               {}
func (n *noopLogger) Print(args ...interface{})                 {}
func (n *noopLogger) Printf(format string, args ...interface{}) {}
func (n *noopLogger) Println(args ...interface{})               {}
func (n *noopLogger) Warnf(format string, args ...interface{})  {}

// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificateappliers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificateappliers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificateappliers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create

func (r *OCPCertificateApplierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	legolog.Logger = &noopLogger{}
	statuses := []certv1.CertificateStatus{}
	count := 0
	log := logf.FromContext(ctx)
	instance, err := r.GetInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Object no longer exists, nothing to do.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	for _, cert := range instance.Spec.CertificatesToCreate {
		status := r.ExtractCertificateStatusFromName(cert.Name, instance)
		switch status.Status {
		case "NonExistant", "Error":
			certSpec := r.ExtractCertificateSpecFromName(cert.Name, instance)
			SignedCeritificate, CertificateStatus, err := r.CreateNewCertificate(ctx, instance, certSpec)
			if err != nil {
				log.Error(err, "failed to sign certificate", "certificate:", cert.Name)
			} else {
				err = r.CreateSecret(ctx, SignedCeritificate)
				if err != nil {
					log.Error(err, "failed to create secret for certificate", "cert", cert.Name)
					CertificateStatus.Status = "Error"
					CertificateStatus.Message = err.Error()
				}
			}
			statuses = append(statuses, CertificateStatus)
		case "Completed":
			count++
			statuses = append(statuses, status)
		case "Signed":
			statuses = append(statuses, status)
		}
	}
	if count == len(instance.Spec.CertificatesToCreate) {
		log.Info("Complete")
		return ctrl.Result{}, err
	}
	instance.Status.Certificates = statuses
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Signed/Error", "instance:", instance)
		return ctrl.Result{}, err
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(err, "Some certificates are in a failed state, cannot proceed", "instance", instance)
		return ctrl.Result{}, errors.New("some certificates failed")
	}
	log.Info("Successfully signed certs.", "instance:", instance)
	err = r.DeleteDirContents("repo")
	if err != nil {
		log.Error(err, "Failed to delete repo contents", "instance:", instance)
		return ctrl.Result{}, err
	}
	err = r.cloneRepo()
	if err != nil {
		log.Error(err, "Failed to clone repo ocpbm-cluster-config", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Successfully cloned git repo.", "instance:", instance)
	repo, wt, err := r.CheckoutBranch()
	if err != nil {
		log.Error(err, "Failed to checkout ocpbm-cluster-config", "instance:", instance)
		return ctrl.Result{}, err
	}
	for _, certificate := range instance.Spec.CertificatesToCreate {
		certSecret, exists, err := r.getSecret(ctx, certificate.Name)
		if err != nil {
			log.Error(err, "failed to fetch secret", "secret:", "signed-"+certificate.Name)
			return ctrl.Result{}, err
		}
		if !exists {
			log.Error(errors.New("secret not found"), "secret not found", "secret:", "signed-"+certificate.Name)
			status := r.CreateCertStatus(certificate.Name, "secret not found", "Error")
			statuses = append(statuses, status)
			continue
		}
		cert := SignedCeritifactes{
			Name:    certSecret.Labels["cert.compute.io/cert-name"],
			GitPath: "/" + strings.ReplaceAll(certSecret.Labels["cert.compute.io/git-path"], ".", "/"),
			Cert:    certSecret.Data["tls.crt"],
			Key:     certSecret.Data["tls.key"],
		}
		encryptedKey, err := r.encryptKey(cert.Key)
		if err != nil {
			log.Error(err, "failed to encrypt key for certificate", "cert:", cert.Name)
			status := r.CreateCertStatus(cert.Name, err.Error(), "Error")
			statuses = append(statuses, status)
			continue
		}
		r.WriteToFile(filepath.Join("/repo", cert.GitPath, "tls.key.enc"), encryptedKey)
		r.WriteToFile(filepath.Join("/repo", cert.GitPath, "tls.crt"), cert.Cert)
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
	err = r.commitAndPushChanges(wt, repo)
	if err != nil {
		log.Error(err, "Failed to commit changes", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Successfully commited and pushed changes.", "instance:", instance)
	mr, err := r.createMergeRequest()
	if err != nil {
		log.Error(err, "Failed to create MR", "instance:", instance)
		return ctrl.Result{}, err
	}
	log.Info("Successfully create MR,", "URL:", mr)
	statuses = []certv1.CertificateStatus{}
	for _, cert := range instance.Status.Certificates {
		status := certv1.CertificateStatus{
			Name:    cert.Name,
			Status:  "Completed",
			Message: "Certificate present in git PR",
		}
		statuses = append(statuses, status)
	}
	instance.Status.Certificates = statuses
	instance.Status.GitPR = mr
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Completed", "instance:", instance)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OCPCertificateApplierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Uncomment the following line adding a pointer to an instance of the controlled resource as an argument
		For(&certv1.OCPCertificateApplier{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{})).
		Named("ocpcertificateapplier").
		Complete(r)
}
