package controller

import (
	"context"
	"errors"
	"fmt"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	"github.com/go-acme/lego/v4/lego"
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
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete

func (r *OCPCertificateApplierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	legolog.Logger = &noopLogger{}
	statuses := []certv1.CertificateStatus{}
	var client *lego.Client
	var user *MyUser
	signingNeeded := false
	acmeSetUp := false
	log := logf.FromContext(ctx)
	instance, err := r.GetInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Object no longer exists, nothing to do.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	acmeMail, pdnsApiKey, err := r.getOperatorData(ctx)
	if err != nil {
		log.Error(err, "Failed to get operator secrets", "instance:", instance)
		return ctrl.Result{}, err
	}

	for _, cert := range instance.Spec.CertificatesToCreate {
		secret, exists, err := r.getSecret(ctx, cert.Name, cert.Namespace)
		if err != nil {
			log.Error(err, "Couldn't lookup secret", "name:", "signed-"+cert.Name)
		}
		if !exists || !r.isDesiredDomains(cert, secret) {
			signingNeeded = true
			if !acmeSetUp {
				privateKey, err := r.GenerateRandomACMEKey()
				if err != nil {
					log.Error(err, "Failed to generate private key", "instance:", instance)
				}
				client, user, err = r.setupACME(acmeMail, privateKey, pdnsApiKey)
				if err != nil {
					log.Error(err, "Failed to setup ACME client", "instance:", instance)
				}
				acmeSetUp = true
			}
			SignedCeritificate, CertificateStatus, err := r.CreateNewCertificate(ctx, instance, cert, client, user)
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

		} else {
			statuses = append(statuses, r.CreateCertStatus(cert.Name, "Successfully signed cert", "Signed", fmt.Sprintf("signed-%s", cert.Name), "ocp-controller-cert-renewer"))
		}
	}
	instance.Status.Certificates = statuses
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Signed/Error", "instance:", instance)
		return ctrl.Result{}, err
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(err, "Some certificates are in a failed state", "instance", instance)
		return ctrl.Result{}, errors.New("some certificates failed")
	}
	if signingNeeded {
		log.Info("Successfully signed certs.", "instance:", instance)
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
