package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

const finalizer = "finalizer.my-operator.compute.io"

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
	}

	acmeMail, pdnsApiKey, acmeHost, pdnsHost, err := r.getOperatorData(ctx, instance)
	if err != nil {
		log.Error(err, "Failed to get operator secrets", "instance:", instance)
		return ctrl.Result{}, err
	}

	privateKey, err := r.GenerateRandomACMEKey()
	if err != nil {
		log.Error(err, "Failed to generate private key", "instance:", instance)
		return ctrl.Result{}, err
	}
	legoClient, user, err := r.setupACME(acmeMail, acmeHost, pdnsHost, pdnsApiKey, privateKey)
	if err != nil {
		log.Error(err, "Failed to setup ACME client", "instance:", instance)
		return ctrl.Result{}, err
	}

	for _, cert := range instance.Spec.Certificates {
		secret := new(corev1.Secret)
		signCert := false
		var errMsg error = nil
		var expiration, status, message string
		secret, exists, err := r.getSecret(cert, ctx)
		if err != nil {
			errMsg = err
			goto finalize
		}
		if !exists {
			err = r.tryUpdatingSecret(ctx, cert.Name, cert.Namespace, instance)
			if err != nil && !apierrors.IsNotFound(err) {
				errMsg = err
				goto finalize
			} else if apierrors.IsNotFound(err) {
				if cert.Domains != nil {
					signCert = true
				} else {
					errMsg = errors.New("cannot issue a new certificate if domains are not specified")
					goto finalize
				}
			}
		}
		if !signCert {
			if cert.Domains == nil {
				domains, err := r.GetCertificateDomains(secret.Data["tls.crt"])
				if err != nil {
					errMsg = err
					goto finalize
				}
				cert.Domains = domains
			}
			if !r.isDesiredDomains(cert, secret) {
				signCert = true
			}
			expiration, status, err = r.UpdateExpiryStatus(ctx, cert, instance, secret)
			if err != nil {
				errMsg = err
				goto finalize
			}
			if status == "About to expire" {
				signCert = true
			}
		}
		if signCert {
			log.Info("new certificate to sign", "name:", cert.Name, "namespace:", cert.Namespace)
			SignedCeritificate, err := r.CreateNewCertificate(ctx, instance, cert, legoClient, user)
			if err != nil {
				errMsg = err
				goto finalize
			} else {
				log.Info("Successfully signed cert", "cert:", cert.Name)
				err = r.CreateSecret(ctx, SignedCeritificate, cert, instance)
				if err != nil {
					errMsg = err
					goto finalize
				}
			}
			secret, _, err := r.getSecret(cert, ctx)
			if err != nil {
				errMsg = err
				goto finalize
			}
			expiration, status, err = r.UpdateExpiryStatus(ctx, cert, instance, secret)
			if err != nil {
				errMsg = err
				goto finalize
			}
		}
		goto finalize

	finalize:
		if errMsg != nil {
			log.Error(errMsg, "failed processing certificate", "certificate:", cert.Name, "namespace:", cert.Namespace)
			statuses = append(statuses, r.CreateCertStatus("Error", errMsg.Error(), "", cert.Name, cert.Namespace))
		} else {
			log.Info("Successfully analyzed cert", "cert:", cert)
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
	return ctrl.Result{RequeueAfter: time.Hour * 24 * 30}, nil
}

func (r *OCPCertificateTrackerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.OCPCertificateTracker{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
				secret, ok := o.(*corev1.Secret)
				if !ok {
					return nil
				}

				ownerKey, ok := secret.Labels["cert.compute.io/managed-by"]
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
