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
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update

func (r *OCPCertificateApplierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	legolog.Logger = &noopLogger{}
	statuses := []certv1.CertificateStatus{}
	var client *lego.Client
	var user *MyUser
	signingNeeded := false
	gitCommitNeeded := false
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

	acmeMail, gitlabToken, pdnsApiKey, err := r.getOperatorData(ctx)
	if err != nil {
		log.Error(err, "Failed to get operator secrets", "instance:", instance)
		return ctrl.Result{}, err
	}

	for _, cert := range instance.Spec.CertificatesToCreate {
		secret, exists, err := r.getSecret(ctx, cert.Name)
		if cert.GitPath != "" && !gitCommitNeeded {
			gitCommitNeeded = true
		}
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
				CertificateStatus.SecretName = "signed-" + CertificateStatus.Name
				CertificateStatus.SecretNamespace = "ocp-controller-cert-renewer"
			}
			statuses = append(statuses, CertificateStatus)

		} else {
			statuses = append(statuses, r.CreateCertStatus(cert.Name, "Successfully signed cert", "Signed", fmt.Sprintf("signed-%s", cert.Name), "ocp-controller-cert-renewer"))
		}
	}
	instance.Status.Certificates = statuses
	if !gitCommitNeeded {
		instance.Status.GitPR = ""
	}
	err = r.UpdateCertificateStatus(ctx, instance)
	if err != nil {
		log.Error(err, "failed to update status at stage Signed/Error", "instance:", instance)
		return ctrl.Result{}, err
	}
	if r.CheckForFailedCerts(ctx, instance, statuses) {
		log.Error(err, "Some certificates are in a failed state, cannot proceed", "instance", instance)
		return ctrl.Result{}, errors.New("some certificates failed")
	}
	if signingNeeded {
		log.Info("Successfully signed certs.", "instance:", instance)
	}
	if gitCommitNeeded {
		branch := instance.Spec.GitBranch
		statuses = []certv1.CertificateStatus{}
		err = DeleteDirContents("repo")
		if err != nil {
			log.Error(err, "Failed to delete repo contents", "instance:", instance)
			return ctrl.Result{}, err
		}
		err = cloneRepo(gitlabToken)
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
		for _, certificate := range instance.Spec.CertificatesToCreate {
			if certificate.GitPath != "" {
				certSecret, exists, err := r.getSecret(ctx, certificate.Name)
				if err != nil {
					log.Error(err, "failed to fetch secret", "secret:", "signed-"+certificate.Name)
					return ctrl.Result{}, err
				}
				if !exists {
					log.Error(errors.New("secret not found"), "secret not found", "secret:", "signed-"+certificate.Name)
					statuses = append(statuses, r.CreateCertStatus(certificate.Name, "secret not found", "Error", "", ""))
					continue
				}
				cert := SignedCeritifactes{
					Name: certSecret.Labels["cert.compute.io/cert-name"],
					Cert: certSecret.Data["tls.crt"],
					Key:  certSecret.Data["tls.key"],
				}
				encryptedKey, err := encryptKey(cert.Key)
				if err != nil {
					log.Error(err, "failed to encrypt key for certificate", "cert:", cert.Name)
					statuses = append(statuses, r.CreateCertStatus(cert.Name, err.Error(), "Error", "", ""))
					continue
				}
				statuses = append(statuses, r.CreateCertStatus(cert.Name, "Key successfully encrypted", "Signed", fmt.Sprintf("signed-%s", cert.Name), "ocp-controller-cert-renewer"))
				WriteToFile("/repo/"+certificate.GitPath+"/tls.key.enc", encryptedKey)
				WriteToFile("/repo/"+certificate.GitPath+"/tls.crt", cert.Cert)
			} else {
				statuses = append(statuses, r.CreateCertStatus(certificate.Name, "Successfully signed cert", "Signed", fmt.Sprintf("signed-%s", certificate.Name), "ocp-controller-cert-renewer"))
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
		err = commitAndPushChanges(wt, repo, branch, gitlabToken)
		if err != nil {
			if err == ErrNoChanges {
				return ctrl.Result{}, nil
			}
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
		statuses = []certv1.CertificateStatus{}
		for _, cert := range instance.Status.Certificates {
			if cert.Message == "Key successfully encrypted" {
				statuses = append(statuses, r.CreateCertStatus(cert.Name, "Certificate present in git PR", "Completed", fmt.Sprintf("signed-%s", cert.Name), "ocp-controller-cert-renewer"))
			} else {
				statuses = append(statuses, r.CreateCertStatus(cert.Name, "Successfully signed cert", "Signed", fmt.Sprintf("signed-%s", cert.Name), "ocp-controller-cert-renewer"))
			}
		}
		instance.Status.Certificates = statuses
		instance.Status.GitPR = mr
		err = r.UpdateCertificateStatus(ctx, instance)
		if err != nil {
			log.Error(err, "failed to update status at stage Completed", "instance:", instance)
			return ctrl.Result{}, err
		}
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
