package controller

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type SignedCeritifactes struct {
	Name string
	Cert []byte
	Key  []byte
}

func (r *OCPCertificateApplierReconciler) GetInstance(ctx context.Context, name string, namespace string) (*certv1.OCPCertificateApplier, error) {
	instance := &certv1.OCPCertificateApplier{}
	err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *OCPCertificateApplierReconciler) CreateSecret(ctx context.Context, signedCert SignedCeritifactes, cert certv1.TargetSecret) error {
	log := logf.FromContext(ctx)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "signed-" + signedCert.Name,
			Namespace: "ocp-controller-cert-renewer",
			Labels: map[string]string{
				"cert.compute.io/cert-name": signedCert.Name,
				"cert.compute.io/domains":   domainsToLabelValue(cert.Dnses),
				"cert.compute.io/git-path":  strings.ReplaceAll(cert.GitPath, "/", "."),
			},
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
			err = r.Update(ctx, secret)
			if err != nil {
				return err
			}
		} else {
			log.Error(err, "Failed to create secret", "secret:", secret)
			return err
		}
	}
	return nil
}

func (r *OCPCertificateApplierReconciler) getSecret(ctx context.Context, name string) (*corev1.Secret, bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      "signed-" + name,
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

func (r *OCPCertificateApplierReconciler) CreateNewCertificate(ctx context.Context, instance *certv1.OCPCertificateApplier, cert certv1.TargetSecret) (SignedCeritifactes, certv1.CertificateStatus, error) {
	log := logf.FromContext(ctx)
	var SignedCert SignedCeritifactes
	var certificateStatus certv1.CertificateStatus
	privateKey, err := r.FetchPrivateKey(ctx)
	if err != nil {
		log.Error(err, "Unable to fetch private key")
		return SignedCeritifactes{}, certv1.CertificateStatus{}, err
	}
	crt, key, err := r.GenerateNewCertificate(instance, ctx, &cert, "orrener2000or@gmail.com", privateKey)
	if err != nil {
		certificateStatus = certv1.CertificateStatus{
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
		certificateStatus = certv1.CertificateStatus{
			Name:    cert.Name,
			Status:  "Signed",
			Message: "Successfully signed certificate",
		}
	}
	return SignedCert, certificateStatus, nil
}

func (r *OCPCertificateApplierReconciler) FetchPrivateKey(ctx context.Context) (crypto.PrivateKey, error) {
	secret := &corev1.Secret{}
	err := r.Client.Get(ctx, types.NamespacedName{
		Name:      "acme-account-key",
		Namespace: "ocp-controller-cert-renewer",
	}, secret)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, _ := pem.Decode(secret.Data["private.key"])
	if privateKeyBytes == nil {
		return nil, errors.New("failed to decode pem block")
	}
	parsedKey, err := x509.ParseECPrivateKey(privateKeyBytes.Bytes)
	if err != nil {
		return nil, err
	}
	return parsedKey, nil

}

func (r *OCPCertificateApplierReconciler) GenerateNewCertificate(instance *certv1.OCPCertificateApplier, ctx context.Context, cert *certv1.TargetSecret, email string, privateKey crypto.PrivateKey) ([]byte, []byte, error) {
	log := logf.FromContext(ctx)
	User := &MyUser{
		Email: email,
		Key:   privateKey,
	}

	client, err := User.SetupLegoClient(User)
	if err != nil {
		log.Error(err, "Failed to set up lego client", "cert:", cert.Name)
		return nil, nil, err
	}
	pdnsProvider, err := User.SetupPDNS()
	if err != nil {
		log.Error(err, "Failed to set up PDNS", "cert:", cert.Name)
		return nil, nil, err
	}
	err = User.SetDNSProvider(client, pdnsProvider)
	if err != nil {
		log.Error(err, "Failed to set up DNS provider for ACME", "cert:", cert.Name)
		return nil, nil, err
	}
	err = User.RegisterClient(User, client)
	if err != nil {
		log.Error(err, "Failed to register user", "cert:", cert.Name)
		return nil, nil, err
	}
	crt, key, err := User.ObtainCertificates(client, cert.Dnses)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func (r *OCPCertificateApplierReconciler) UpdateCertificateStatus(ctx context.Context, instance *certv1.OCPCertificateApplier) error {

	err := r.Status().Update(ctx, instance)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update instance status:", "instance:", instance)
		return err
	}
	return nil
}

func (r *OCPCertificateApplierReconciler) CheckForFailedCerts(ctx context.Context, instance *certv1.OCPCertificateApplier, certs []certv1.CertificateStatus) bool {

	for _, cert := range certs {
		if cert.Status == "Error" {
			return true
		}
	}
	return false
}

func (r *OCPCertificateApplierReconciler) CheckForCompletedCerts(ctx context.Context, instance *certv1.OCPCertificateApplier, certs []certv1.CertificateStatus) bool {
	count := 0
	for _, cert := range certs {
		if cert.Status == "Completed" {
			count += 1
		}
	}
	return count == len(certs) && count != 0
}

func (r *OCPCertificateApplierReconciler) DeleteSelf(ctx context.Context, instance *certv1.OCPCertificateApplier) error {
	err := r.Delete(ctx, instance)
	if err != nil {
		return err
	}
	return nil
}

func (r *OCPCertificateApplierReconciler) CreateCertStatus(name, message, status, secretName, secretNamespace string) certv1.CertificateStatus {
	return certv1.CertificateStatus{
		Name:            name,
		Status:          status,
		Message:         message,
		SecretName:      secretName,
		SecretNamespace: secretNamespace,
	}
}

func (r *OCPCertificateApplierReconciler) ExtractCertificateSpecFromName(name string, instance *certv1.OCPCertificateApplier) certv1.TargetSecret {
	for _, cert := range instance.Spec.CertificatesToCreate {
		if cert.Name == name {
			return cert
		}
	}
	return certv1.TargetSecret{}
}

func (r *OCPCertificateApplierReconciler) ExtractCertificateStatusFromName(name string, instance *certv1.OCPCertificateApplier) certv1.CertificateStatus {
	for _, cert := range instance.Status.Certificates {
		if cert.Name == name {
			return cert
		}
	}
	return certv1.CertificateStatus{
		Status: "NonExistant",
	}
}

func domainsToLabelValue(domains []string) string {
	sort.Strings(domains)
	joinedDomains := strings.Join(domains, ",")

	hasher := sha256.New()
	hasher.Write([]byte(joinedDomains))
	hash := hasher.Sum(nil)

	hashString := hex.EncodeToString(hash)
	return hashString[0:32]
}

func (r *OCPCertificateApplierReconciler) isDesiredDomains(cert certv1.TargetSecret, secret *corev1.Secret) bool {
	return domainsToLabelValue(cert.Dnses) == secret.Labels["cert.compute.io/domains"]
}
