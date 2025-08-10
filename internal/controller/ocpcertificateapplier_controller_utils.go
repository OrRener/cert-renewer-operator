package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	"github.com/go-acme/lego/v4/lego"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func (r *OCPCertificateApplierReconciler) GenerateRandomACMEKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (r *OCPCertificateApplierReconciler) getOperatorData(ctx context.Context) (string, string, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      "operator-data-secret",
		Namespace: "ocp-controller-cert-renewer",
	}, secret)

	if err != nil {
		return "", "", fmt.Errorf("failed to get secret: %w", err)
	}

	if string(secret.Data["acmeMail"]) == "" {
		return "", "", errors.New("acmeMail is empty")
	} else if string(secret.Data["pdnsApiKey"]) == "" {
		return "", "", errors.New("pdnsApiKey is empty")
	}

	return string(secret.Data["acmeMail"]), string(secret.Data["pdnsApiKey"]), nil
}

func (r *OCPCertificateApplierReconciler) CreateSecret(ctx context.Context, signedCert SignedCeritifactes, cert certv1.TargetSecret) error {
	log := logf.FromContext(ctx)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Name,
			Namespace: cert.Namespace,
			Labels: map[string]string{
				"cert.compute.io/domains": domainsToLabelValue(cert.Dnses),
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

func (r *OCPCertificateApplierReconciler) getSecret(ctx context.Context, name, namespace string) (*corev1.Secret, bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}, secret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get secret: %w", err)
	}
	return secret, true, nil
}

func (r *OCPCertificateApplierReconciler) CreateNewCertificate(ctx context.Context, instance *certv1.OCPCertificateApplier, cert certv1.TargetSecret, client *lego.Client, User *MyUser) (SignedCeritifactes, certv1.CertificateStatus, error) {
	var SignedCert SignedCeritifactes
	var certificateStatus certv1.CertificateStatus
	crt, key, err := r.GenerateNewCertificate(client, User, &cert)
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

func (r *OCPCertificateApplierReconciler) setupACME(email string, privateKey crypto.PrivateKey, apiKey string) (*lego.Client, *MyUser, error) {
	User := &MyUser{
		Email: email,
		Key:   privateKey,
	}
	client, err := User.SetupLegoClient(User)
	if err != nil {
		return nil, nil, err
	}
	pdnsProvider, err := User.SetupPDNS(apiKey)
	if err != nil {
		return nil, nil, err
	}
	err = User.SetDNSProvider(client, pdnsProvider)
	if err != nil {
		return nil, nil, err
	}
	err = User.RegisterClient(User, client)
	if err != nil {
		return nil, nil, err
	}
	return client, User, nil
}

func (r *OCPCertificateApplierReconciler) GenerateNewCertificate(client *lego.Client, User *MyUser, cert *certv1.TargetSecret) ([]byte, []byte, error) {
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

func (r *OCPCertificateApplierReconciler) CreateCertStatus(name, message, status, secretName, secretNamespace string) certv1.CertificateStatus {
	return certv1.CertificateStatus{
		Name:    name,
		Status:  status,
		Message: message,
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
