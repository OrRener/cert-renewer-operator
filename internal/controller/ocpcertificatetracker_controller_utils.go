package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	"github.com/go-acme/lego/v4/lego"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func ParseDaysDuration(threshold string) (string, error) {
	daysStr := strings.TrimSuffix(threshold, "d")
	daysInt, err := strconv.Atoi(daysStr)
	if err != nil {
		return "", fmt.Errorf("invalid day number: %w", err)
	}

	return (time.Hour * 24 * time.Duration(daysInt)).String(), nil
}

func (r *OCPCertificateTrackerReconciler) UpdateObjectStatus(ctx context.Context, instance *certv1.OCPCertificateTracker) error {
	err := r.Status().Update(ctx, instance)
	if err != nil {
		return err
	}
	return nil
}

func (r *OCPCertificateTrackerReconciler) FetchInstance(ctx context.Context, name string, namespace string) (*certv1.OCPCertificateTracker, error) {
	instance := &certv1.OCPCertificateTracker{}
	err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *OCPCertificateTrackerReconciler) FindExpirationOfCertificate(ctx context.Context, certData []byte) (string, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	expiration := cert.NotAfter
	return expiration.String(), nil
}

func (r *OCPCertificateTrackerReconciler) CheckIfValidCertificate(expiration string, instance *certv1.OCPCertificateTracker) (string, error) {
	expirationTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", strings.TrimSpace(expiration))
	var timeToParse string
	if err != nil {
		return "Error", fmt.Errorf("failed to parse expiration time: %v", err)
	}

	if expirationTime.Before(metav1.Now().Time) {
		return "Expired", nil
	}
	if strings.HasSuffix(instance.Spec.ExpirationThreshold, "d") {
		timeToParse, err = ParseDaysDuration(instance.Spec.ExpirationThreshold)
		if err != nil {
			return "Error", fmt.Errorf("failed to parse expiration threshold: %v", err)
		}
	} else {
		timeToParse = instance.Spec.ExpirationThreshold
	}
	thresholdDuration, err := time.ParseDuration(timeToParse)
	if err != nil {
		return "Invalid", fmt.Errorf("failed to parse threshold duration: %v", err)
	}
	if expirationTime.Before(metav1.Now().Add(thresholdDuration)) {
		return "About to expire", nil
	}
	return "Valid", nil
}

func (r *OCPCertificateTrackerReconciler) getSecret(cert certv1.CertificatesStruct, ctx context.Context) (*corev1.Secret, bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      cert.Name,
		Namespace: cert.Namespace,
	}, secret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get secret: %w", err)
	}
	return secret, true, nil
}

func (r *OCPCertificateTrackerReconciler) UpdateExpiryStatus(ctx context.Context, cert certv1.CertificatesStruct, instance *certv1.OCPCertificateTracker, secret *corev1.Secret) (string, string, error) {
	if secret == nil {
		return "", "", errors.New("empty secret")
	}
	certData, exists := secret.Data["tls.crt"]
	if !exists {
		err := errors.New("data not found")
		return "", "", err
	}
	expiration, err := r.FindExpirationOfCertificate(ctx, certData)
	if err != nil {
		return "", "", err
	}
	status, err := r.CheckIfValidCertificate(expiration, instance)
	if err != nil {
		return "", "", err
	}

	return expiration, status, nil
}

func (r *OCPCertificateTrackerReconciler) GetCertificateDomains(certData []byte) ([]string, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	domains := cert.DNSNames
	if len(domains) == 0 {
		domains = []string{cert.Subject.CommonName}
	}
	return domains, nil
}

func (r *OCPCertificateTrackerReconciler) CreateOCPCertificateApplier(ctx context.Context, AboutToExpireCerts []AboutToExpireCertificates, instance *certv1.OCPCertificateTracker) error {
	var certInputs []certv1.TargetSecret
	for _, cert := range AboutToExpireCerts {
		certInputs = append(certInputs, certv1.TargetSecret{
			Name:      cert.Name,
			Namespace: cert.Namespace,
			Dnses:     cert.Domains,
		})
	}
	certCR := &certv1.OCPCertificateApplier{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name + "-applier",
			Namespace: "ocp-controller-cert-renewer",
		},
		Spec: certv1.OCPCertificateApplierSpec{
			CertificatesToCreate: certInputs,
		},
	}
	existing := &certv1.OCPCertificateApplier{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      certCR.Name,
		Namespace: certCR.Namespace,
	}, existing)

	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if apierrors.IsNotFound(err) {
		return r.Create(ctx, certCR)
	}

	existing.Spec = certCR.Spec
	if err := r.Update(ctx, existing); err != nil {
		return err
	}

	return nil
}

func (r *OCPCertificateTrackerReconciler) CreateCertStatus(status, message, expiry, name, namespace string) certv1.CertificatesStatusStruct {
	return certv1.CertificatesStatusStruct{
		Name:        name,
		Namespace:   namespace,
		Status:      status,
		Message:     message,
		LastChecked: metav1.Now(),
		Expiry:      expiry,
	}
}

func (r *OCPCertificateTrackerReconciler) CheckForFailedCerts(ctx context.Context, instance *certv1.OCPCertificateTracker, certs []certv1.CertificatesStatusStruct) bool {

	for _, cert := range certs {
		if cert.Status == "Error" {
			return true
		}
	}
	return false
}

func (r *OCPCertificateTrackerReconciler) GenerateRandomACMEKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (r *OCPCertificateTrackerReconciler) getOperatorData(ctx context.Context) (string, string, error) {
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

func (r *OCPCertificateTrackerReconciler) tryUpdatingSecret(ctx context.Context, name, namespace string, instance *certv1.OCPCertificateTracker) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}

	patch := client.MergeFrom(secret.DeepCopy())
	secret.Labels = map[string]string{
		"cert.compute.io/managed-by": instance.Name,
	}

	return r.Client.Patch(ctx, secret, patch)
}

func (r *OCPCertificateTrackerReconciler) CreateSecret(ctx context.Context, signedCert SignedCeritifactes, cert certv1.CertificatesStruct, instance *certv1.OCPCertificateTracker) error {
	log := logf.FromContext(ctx)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Name,
			Namespace: cert.Namespace,
			Labels: map[string]string{
				"cert.compute.io/domains":    domainsToLabelValue(cert.Domains),
				"cert.compute.io/managed-by": instance.Name,
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

func (r *OCPCertificateTrackerReconciler) CreateNewCertificate(ctx context.Context, instance *certv1.OCPCertificateTracker, cert certv1.CertificatesStruct, client *lego.Client, User *MyUser) (SignedCeritifactes, error) {
	var SignedCert SignedCeritifactes
	crt, key, err := r.GenerateNewCertificate(client, User, &cert)
	if err != nil {
		return SignedCeritifactes{}, err
	}
	expiry, err := r.FindExpirationOfCertificate(ctx, crt)
	if err != nil {
		return SignedCeritifactes{}, nil
	}
	fmt.Println(expiry)
	SignedCert = SignedCeritifactes{
		Name:   cert.Name,
		Cert:   crt,
		Key:    key,
		Expiry: expiry,
	}

	return SignedCert, nil
}

func (r *OCPCertificateTrackerReconciler) setupACME(email string, privateKey crypto.PrivateKey, apiKey string) (*lego.Client, *MyUser, error) {
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

func (r *OCPCertificateTrackerReconciler) GenerateNewCertificate(client *lego.Client, User *MyUser, cert *certv1.CertificatesStruct) ([]byte, []byte, error) {
	crt, key, err := User.ObtainCertificates(client, cert.Domains)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func (r *OCPCertificateTrackerReconciler) UpdateCertificateStatus(ctx context.Context, instance *certv1.OCPCertificateTracker) error {

	err := r.Status().Update(ctx, instance)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update instance status:", "instance:", instance)
		return err
	}
	return nil
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

func (r *OCPCertificateTrackerReconciler) isDesiredDomains(cert certv1.CertificatesStruct, secret *corev1.Secret) bool {
	return domainsToLabelValue(cert.Domains) == secret.Labels["cert.compute.io/domains"]
}
