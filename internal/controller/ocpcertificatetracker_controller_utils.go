package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
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

func (r *OCPCertificateTrackerReconciler) CheckIfValidCertificate(ctx context.Context, expiration string, instance *certv1.OCPCertificateTracker) (string, error) {
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
	logf.FromContext(ctx).Info("Checking certificate validity", "expirationTime", expirationTime, "thresholdDuration", thresholdDuration)
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

func (r *OCPCertificateTrackerReconciler) UpdateExpiryStatus(ctx context.Context, cert certv1.CertificatesStruct, instance *certv1.OCPCertificateTracker, secret *corev1.Secret) (certv1.CertificatesStatusStruct, error) {
	var Status string = "Error"
	certData, exists := secret.Data["tls.crt"]
	if !exists {
		err := errors.New("data not found")
		return r.CreateCertStatus(Status, err.Error(), "", cert.Name, cert.Namespace), err
	}
	expiration, err := r.FindExpirationOfCertificate(ctx, certData)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to find certificate expiration", "name", cert.Name, "namespace", cert.Namespace)
		return r.CreateCertStatus(Status, err.Error(), "", cert.Name, cert.Namespace), errors.New("couldn't find expiration date")
	}
	Status, err = r.CheckIfValidCertificate(ctx, expiration, instance)
	if err != nil {
		return r.CreateCertStatus(Status, err.Error(), "", cert.Name, cert.Namespace), err
	}
	Message := fmt.Sprintf("Certificate %s in namespace %s expires at %s", cert.Name, cert.Namespace, expiration)
	Expiry := expiration

	logf.FromContext(ctx).Info("Fetched certificates expiry details", "certificate", cert.Name)
	return r.CreateCertStatus(Status, Message, Expiry, cert.Name, cert.Namespace), nil
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

func (r *OCPCertificateTrackerReconciler) createAboutToExpireStruct(name, namespace string, domains []string) AboutToExpireCertificates {
	return AboutToExpireCertificates{
		Name:      name,
		Namespace: namespace,
		Domains:   domains,
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
