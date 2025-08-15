package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	legolog "github.com/go-acme/lego/v4/log"
)

type noopLogger struct{}

func (n *noopLogger) Fatal(args ...interface{})                 {}
func (n *noopLogger) Fatalf(format string, args ...interface{}) {}
func (n *noopLogger) Fatalln(args ...interface{})               {}
func (n *noopLogger) Print(args ...interface{})                 {}
func (n *noopLogger) Printf(format string, args ...interface{}) {}
func (n *noopLogger) Println(args ...interface{})               {}
func (n *noopLogger) Warnf(format string, args ...interface{})  {}

type OCPCertificateTrackerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type AboutToExpireCertificates struct {
	Name      string
	Namespace string
	Domains   []string
}

type SignedCeritifactes struct {
	Name   string
	Cert   []byte
	Key    []byte
	Expiry string
}

// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete;patch

func (r *OCPCertificateTrackerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	legolog.Logger = &noopLogger{}
	log := logf.FromContext(ctx)
	statuses := []certv1.CertificatesStatusStruct{}

	instance, err := r.FetchInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		log.Error(err, "Failed to fetch OCPCertificateTracker")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	acmeMail, pdnsApiKey, err := r.getOperatorData(ctx)
	if err != nil {
		log.Error(err, "Failed to get operator secrets", "instance:", instance)
		return ctrl.Result{}, err
	}

	privateKey, err := r.GenerateRandomACMEKey()
	if err != nil {
		log.Error(err, "Failed to generate private key", "instance:", instance)
		return ctrl.Result{}, err
	}
	client, user, err := r.setupACME(acmeMail, privateKey, pdnsApiKey)
	if err != nil {
		log.Error(err, "Failed to setup ACME client", "instance:", instance)
		return ctrl.Result{}, err
	}

	for _, cert := range instance.Spec.Certificates {
		secret := &corev1.Secret{}
		signCert := false
		var err error
		var expiration, status, message string
		secret, exists, err := r.getSecret(cert, ctx)
		if err != nil {
			goto finalize
		}
		if !exists {
			err = r.tryUpdatingSecret(ctx, cert.Name, cert.Namespace, instance)
			if err != nil && !apierrors.IsNotFound(err) {
				goto finalize
			} else if apierrors.IsNotFound(err) {
				if cert.Domains != nil {
					signCert = true
				} else {
					err = errors.New("cannot issue a new certificate if domains are not specified")
					goto finalize
				}
			}
		}
		if !signCert {
			if cert.Domains == nil {
				domains, err := r.GetCertificateDomains(secret.Data["tls.crt"])
				if err != nil {
					goto finalize
				}
				cert.Domains = domains
			}
			if !r.isDesiredDomains(cert, secret) {
				signCert = true
			}
			expiration, status, err = r.UpdateExpiryStatus(ctx, cert, instance, secret)
			if err != nil {
				goto finalize
			}
			if status == "About to expire" {
				signCert = true
			}
		}
		if signCert {
			log.Info("new certificate to sign", "name:", cert.Name, "namespace:", cert.Namespace)
			SignedCeritificate, err := r.CreateNewCertificate(ctx, instance, cert, client, user)
			if err != nil {
				goto finalize
			} else {
				log.Info("Successfully signed cert", "cert:", cert.Name)
				err = r.CreateSecret(ctx, SignedCeritificate, cert, instance)
				if err != nil {
					goto finalize
				}

			}
			expiration, status, err = r.UpdateExpiryStatus(ctx, cert, instance, secret)
			if err != nil {
				goto finalize
			}
		}
		err = nil
		goto finalize

	finalize:
		if err != nil {
			log.Error(err, "failed processing certificate", "certificate:", cert.Name, "namespace:", cert.Namespace)
			statuses = append(statuses, r.CreateCertStatus("Error", err.Error(), "", cert.Name, cert.Namespace))
		} else {
			log.Info("Successfully analyzed cert")
			message = fmt.Sprintf("Certificate %v in namespace %v expires at %s", cert.Name, cert.Namespace, expiration)
			statuses = append(statuses, r.CreateCertStatus(status, message, expiration, cert.Name, cert.Namespace))
		}
		instance.Status.Certificates = statuses
		err = r.UpdateObjectStatus(ctx, instance)
		if err != nil {
			log.Error(err, "failed to update status field", "instance:", instance)
			return ctrl.Result{}, err
		}
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(errors.New("some certificates failed"), "Some certificates are in a failed state, cannot proceed", "instance", instance)
	}
	return ctrl.Result{}, nil
}

func (r *OCPCertificateTrackerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.OCPCertificateTracker{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{})).
		Named("ocpcertificatetracker").
		Complete(r)
}
