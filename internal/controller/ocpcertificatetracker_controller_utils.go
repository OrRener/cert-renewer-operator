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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

const (
	errorStatus = "Error"
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
		return errorStatus, fmt.Errorf("failed to parse expiration time: %v", err)
	}

	if expirationTime.Before(metav1.Now().Time) {
		return "Expired", nil
	}
	if strings.HasSuffix(instance.Spec.ExpirationThreshold, "d") {
		timeToParse, err = ParseDaysDuration(instance.Spec.ExpirationThreshold)
		if err != nil {
			return errorStatus, fmt.Errorf("failed to parse expiration threshold: %v", err)
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

func (r *OCPCertificateTrackerReconciler) UpdateExpiryStatus(ctx context.Context, instance *certv1.OCPCertificateTracker, cert []byte) (string, string, error) {
	expiration, err := r.FindExpirationOfCertificate(ctx, cert)
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
		if cert.Status == errorStatus {
			return true
		}
	}
	return false
}

func (r *OCPCertificateTrackerReconciler) GenerateRandomACMEKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (r *OCPCertificateTrackerReconciler) getOperatorData(ctx context.Context, instance *certv1.OCPCertificateTracker) (string, string, string, string, error) {
	secret := &corev1.Secret{}
	issuerConfig := &certv1.IssuerConfig{}

	if instance.Spec.IssuerConfigRef.Namespace == "" {
		instance.Spec.IssuerConfigRef.Namespace = instance.Namespace
	}

	err := r.Get(ctx, client.ObjectKey{
		Name:      instance.Spec.IssuerConfigRef.Name,
		Namespace: instance.Spec.IssuerConfigRef.Namespace,
	}, issuerConfig)

	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to get issuerConfig: %w", err)
	}

	if issuerConfig.Spec.AcmeSecret.SecretRef.Namespace == "" {
		issuerConfig.Spec.AcmeSecret.SecretRef.Namespace = issuerConfig.Namespace
	}
	err = r.Get(ctx, client.ObjectKey{
		Name:      issuerConfig.Spec.AcmeSecret.SecretRef.Name,
		Namespace: issuerConfig.Spec.AcmeSecret.SecretRef.Namespace,
	}, secret)

	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to get secret: %w", err)
	}

	if string(secret.Data["acmeMail"]) == "" {
		return "", "", "", "", errors.New("acmeMail is empty")
	} else if string(secret.Data["pdnsApiKey"]) == "" {
		return "", "", "", "", errors.New("pdnsApiKey is empty")
	} else if string(secret.Data["acmeHost"]) == "" {
		return "", "", "", "", errors.New("acmeHost is empty")
	} else if string(secret.Data["pdnsHost"]) == "" {
		return "", "", "", "", errors.New("pdnsHost is empty")
	}

	return string(secret.Data["acmeMail"]), string(secret.Data["pdnsApiKey"]), string(secret.Data["acmeHost"]), string(secret.Data["pdnsHost"]), nil
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
		"cert.compute.io/managed-by": fmt.Sprintf("%s.%s", instance.Namespace, instance.Name),
		"cert.compute.io/managed":    "true",
	}

	return r.Patch(ctx, secret, patch)
}

func (r *OCPCertificateTrackerReconciler) CreateSecret(ctx context.Context, signedCert SignedCertificates, cert certv1.CertificatesStruct, instance *certv1.OCPCertificateTracker) error {
	log := logf.FromContext(ctx)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Name,
			Namespace: cert.Namespace,
			Labels: map[string]string{
				"cert.compute.io/domains":    domainsToLabelValue(cert.Domains),
				"cert.compute.io/managed-by": fmt.Sprintf("%s.%s", instance.Namespace, instance.Name),
				"cert.compute.io/managed":    "true",
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

func (r *OCPCertificateTrackerReconciler) CreateNewCertificate(ctx context.Context, instance *certv1.OCPCertificateTracker, cert certv1.CertificatesStruct, legoClient *lego.Client, User *MyUser) (SignedCertificates, error) {
	var SignedCert SignedCertificates
	crt, key, err := r.GenerateNewCertificate(legoClient, User, &cert)
	if err != nil {
		return SignedCertificates{}, err
	}
	expiry, err := r.FindExpirationOfCertificate(ctx, crt)
	if err != nil {
		return SignedCertificates{}, nil
	}
	SignedCert = SignedCertificates{
		Name:   cert.Name,
		Cert:   crt,
		Key:    key,
		Expiry: expiry,
	}

	return SignedCert, nil
}

func (r *OCPCertificateTrackerReconciler) setupACME(email, acmeHost, pdnsHost, apiKey string, privateKey crypto.PrivateKey) (*lego.Client, *MyUser, error) {
	User := &MyUser{
		Email: email,
		Key:   privateKey,
	}
	legoClient, err := User.SetupLegoClient(User, acmeHost)
	if err != nil {
		return nil, nil, err
	}
	pdnsProvider, err := User.SetupPDNS(apiKey, pdnsHost)
	if err != nil {
		return nil, nil, err
	}
	err = User.SetDNSProvider(legoClient, pdnsProvider)
	if err != nil {
		return nil, nil, err
	}
	err = User.RegisterClient(User, legoClient)
	if err != nil {
		return nil, nil, err
	}
	return legoClient, User, nil
}

func (r *OCPCertificateTrackerReconciler) GenerateNewCertificate(legoClient *lego.Client, User *MyUser, cert *certv1.CertificatesStruct) ([]byte, []byte, error) {
	crt, key, err := User.ObtainCertificates(legoClient, cert.Domains)
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

func (r *OCPCertificateTrackerReconciler) cleanup(ctx context.Context) error {

	selector, err := labels.NewRequirement("cert.compute.io/managed-by", selection.Exists, nil)
	if err != nil {
		return fmt.Errorf("failed to create label selector for cleanup: %w", err)
	}

	secretList := &corev1.SecretList{}
	listOpts := []client.ListOption{
		client.MatchingLabelsSelector{Selector: labels.NewSelector().Add(*selector)},
	}

	if err := r.List(ctx, secretList, listOpts...); err != nil {
		return fmt.Errorf("failed to list secrets for cleanup: %w", err)
	}

	for _, secret := range secretList.Items {
		secretToUpdate := secret.DeepCopy()

		if secretToUpdate.Labels != nil {
			delete(secretToUpdate.Labels, "cert.compute.io/managed-by")
		}
		if err := r.Patch(ctx, secretToUpdate, client.MergeFrom(&secret)); err != nil {
			return fmt.Errorf("failed to remove label from secret %s: %w", secretToUpdate.Name, err)
		}
	}

	return nil
}
