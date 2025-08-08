package controller

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	"github.com/go-acme/lego/v4/lego"
)

func (r *OCPNewCertificateRequestReconciler) FetchInstance(ctx context.Context, name string, namespace string) (*certv1.OCPNewCertificateRequest, error) {
	instance := &certv1.OCPNewCertificateRequest{}
	err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *OCPNewCertificateRequestReconciler) ExtractCertificateStatusFromName(name string, instance *certv1.OCPNewCertificateRequest) certv1.CertificateRequestStatus {
	for _, cert := range instance.Status.Certificates {
		if cert.Name == name {
			return cert
		}
	}
	return certv1.CertificateRequestStatus{
		Status: "NonExistant",
	}
}

func (r *OCPNewCertificateRequestReconciler) generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (r *OCPNewCertificateRequestReconciler) CreateNewCertificate(ctx context.Context, instance *certv1.OCPNewCertificateRequest, cert certv1.CertificateRequest, user MyUser, client *lego.Client) (SignedCeritifactes, certv1.CertificateRequestStatus, error) {
	var SignedCert SignedCeritifactes
	var certificateStatus certv1.CertificateRequestStatus

	crt, key, err := r.GenerateNewCertificate(ctx, &cert, client, user)
	if err != nil {
		certificateStatus = certv1.CertificateRequestStatus{
			Name:    cert.Name,
			Status:  "Error",
			Message: fmt.Sprintf("Failed to sign certificate: %v The CR won't continue till this is solved!!", err),
		}
		return SignedCeritifactes{}, certificateStatus, err
	} else {
		SignedCert = SignedCeritifactes{
			Name: cert.Name,
			Cert: crt,
			Key:  key,
		}
		certificateStatus = certv1.CertificateRequestStatus{
			Name:    cert.Name,
			Status:  "Signed",
			Message: "Successfully signed certificate",
		}
	}
	return SignedCert, certificateStatus, nil
}

func (r *OCPNewCertificateRequestReconciler) SetupACME(ctx context.Context, instance *certv1.OCPNewCertificateRequest, email string, privateKey crypto.PrivateKey) (*MyUser, *lego.Client, error) {
	log := logf.FromContext(ctx)
	User := &MyUser{
		Email: email,
		Key:   privateKey,
	}

	client, err := User.SetupLegoClient(User)
	if err != nil {
		log.Error(err, "Failed to set up lego client", "instance:", instance)
		return nil, nil, err
	}
	pdnsProvider, err := User.SetupPDNS()
	if err != nil {
		log.Error(err, "Failed to set up PDNS", "instance:", instance)
		return nil, nil, err
	}
	err = User.SetDNSProvider(client, pdnsProvider)
	if err != nil {
		log.Error(err, "Failed to set up DNS provider for ACME", "instance:", instance)
		return nil, nil, err
	}
	err = User.RegisterClient(User, client)
	if err != nil {
		log.Error(err, "Failed to register user", "instance:", instance)
		return nil, nil, err
	}
	return User, client, nil
}

func (r *OCPNewCertificateRequestReconciler) GenerateNewCertificate(ctx context.Context, cert *certv1.CertificateRequest, client *lego.Client, User MyUser) ([]byte, []byte, error) {
	crt, key, err := User.ObtainCertificates(client, cert.Domains)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func (r *OCPNewCertificateRequestReconciler) CreateSecret(ctx context.Context, signedCert SignedCeritifactes, cert certv1.CertificateRequest) error {
	log := logf.FromContext(ctx)
	var labels map[string]string
	if cert.GitPath != "" {
		labels =
			map[string]string{
				"cert.compute.io/cert-name": cert.Name,
				"cert.compute.io/git-path":  strings.ReplaceAll(cert.GitPath, "/", "."),
			}
	} else {
		labels =
			map[string]string{
				"cert.compute.io/cert-name": cert.Name,
			}
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-" + cert.Name,
			Namespace: "ocp-controller-cert-renewer",
			Labels:    labels,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       signedCert.Cert,
			corev1.TLSPrivateKeyKey: signedCert.Key,
		},
	}
	err := r.Create(ctx, secret)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		} else {
			log.Error(err, "Failed to create secret", "secret:", secret)
			return err
		}
	}
	return nil
}

func (r *OCPNewCertificateRequestReconciler) getSecret(ctx context.Context, name string) (*corev1.Secret, bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      "new-" + name,
		Namespace: "ocp-controller-cert-renewer",
	}, secret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get secret: %w", err)
	}
	return secret, true, nil
}

func (r *OCPNewCertificateRequestReconciler) CheckForFailedCerts(ctx context.Context, instance *certv1.OCPNewCertificateRequest, certs []certv1.CertificateRequestStatus) bool {

	for _, cert := range certs {
		if cert.Status == "Error" {
			return true
		}
	}
	return false
}

func (r *OCPNewCertificateRequestReconciler) UpdateCertificateStatus(ctx context.Context, instance *certv1.OCPNewCertificateRequest) error {

	err := r.Status().Update(ctx, instance)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update instance status:", "instance:", instance)
		return err
	}
	return nil
}

func (r *OCPNewCertificateRequestReconciler) CreateCertStatus(name, message, status string) certv1.CertificateRequestStatus {
	return certv1.CertificateRequestStatus{
		Name:    name,
		Status:  status,
		Message: message,
	}
}
