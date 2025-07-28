/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certv1 "github.com/OrRener/cert-renewer-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// OCPCertificateTrackerReconciler reconciles a OCPCertificateTracker object
type OCPCertificateTrackerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type CertStatus struct {
	Name      string
	Namespace string
	Secret    corev1.Secret
	CaCert    string
	Message   string
	Status    string `json:"status,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
}

type AboutToExpireCertificates struct {
	Name        string
	Namespace   string
	Application string
}

// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert.compute.io,resources=ocpcertificatetrackers/finalizers,verbs=update
/// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OCPCertificateTracker object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile

func ParseDaysDuration(threshold string) (string, error) {
	daysStr := strings.TrimSuffix(threshold, "d")
	daysInt, err := strconv.Atoi(daysStr)
	if err != nil {
		return "", fmt.Errorf("invalid day number: %w", err)
	}

	return (time.Hour * 24 * time.Duration(daysInt)).String(), nil
}

func (r *OCPCertificateTrackerReconciler) CreateObjectStatus(ctx context.Context, instance *certv1.OCPCertificateTracker, secrets []CertStatus) {
	log := logf.FromContext(ctx)
	log.Info("Updating OCPCertificateTracker status with error", "name", instance.Name, "namespace", instance.Namespace)
	var statuses []certv1.CertificatesStatusStruct

	for _, secret := range secrets {
		status := certv1.CertificatesStatusStruct{
			Name:        secret.Name,
			Namespace:   secret.Namespace,
			Status:      secret.Status,
			Message:     secret.Message,
			LastChecked: metav1.Now(),
			Expiry:      secret.Expiry,
		}
		statuses = append(statuses, status)
	}
	instance.Status.Certificates = statuses
}

func (r *OCPCertificateTrackerReconciler) UpdateObjectStatus(ctx context.Context, instance *certv1.OCPCertificateTracker) error {
	log := logf.FromContext(ctx)
	log.Info("Updating OCPCertificateTracker status", "name", instance.Name, "namespace", instance.Namespace)

	err := r.Status().Update(ctx, instance)
	if err != nil {
		log.Error(err, "Failed to update OCPCertificateTracker status")
		return err
	}
	log.Info("Successfully updated OCPCertificateTracker status")
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

func (r *OCPCertificateTrackerReconciler) ReadSecrets(ctx context.Context, instance *certv1.OCPCertificateTracker) []CertStatus {
	log := logf.FromContext(ctx)
	log.Info("Reading certificates from OCPCertificateTracker", "name", instance.Name, "namespace", instance.Namespace)
	var statuses []CertStatus
	var Message string
	var Status string
	certificates := instance.Spec.Certificates
	for _, cert := range certificates {
		secret := &corev1.Secret{}
		secretKey := types.NamespacedName{
			Name:      cert.Name,
			Namespace: cert.Namespace,
		}
		err := r.Client.Get(ctx, secretKey, secret)
		if err != nil {
			Message = fmt.Sprintf("Failed to get secret %s in namespace %s: %v", cert.Name, cert.Namespace, err)
			logf.FromContext(ctx).Error(err, Message)
			Status = "Error"

		} else {
			logf.FromContext(ctx).Info("Successfully fetched secret", "name", secret.Name, "namespace", secret.Namespace)
		}
		status := CertStatus{
			Secret:    *secret,
			Name:      cert.Name,
			Namespace: cert.Namespace,
			CaCert:    cert.CaCert,
			Status:    Status,
			Message:   Message,
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (r *OCPCertificateTrackerReconciler) GetAboutToExpireCertificatesApplication(ctx context.Context, certs []CertStatus) []AboutToExpireCertificates {

	var aboutToExpire []AboutToExpireCertificates
	var AboutToExpireCerts []AboutToExpireCertificates

	for _, status := range certs {
		if status.Status == "About to expire" {
			app := status.Secret.Labels["app.kubernetes.io/instance"]
			aboutToExpire = append(aboutToExpire, AboutToExpireCertificates{
				Name:        status.Name,
				Namespace:   status.Namespace,
				Application: app,
			})
		}
	}
	AboutToExpireCerts = aboutToExpire
	return AboutToExpireCerts
}

func (r *OCPCertificateTrackerReconciler) UpdateExpiryStatus(ctx context.Context, statuses []CertStatus, instance *certv1.OCPCertificateTracker) []CertStatus {
	var CertList []CertStatus
	var Status string = "Error"

	for _, cert := range statuses {
		if cert.Message != "" {
			CertList = append(CertList, cert)
			continue
		}
		logf.FromContext(ctx).Info("Checking certificate expiry", "name", cert.Name, "namespace", cert.Namespace)
		cert.Status = Status
		certData, exists := cert.Secret.Data[cert.CaCert]
		if !exists {
			logf.FromContext(ctx).Error(nil, "Certificate data not found in secret", "name", cert.Name, "namespace", cert.Namespace)
			cert.Message = fmt.Sprintf("Certificate data %s not found in secret %s in namespace %s", cert.CaCert, cert.Name, cert.Namespace)
			CertList = append(CertList, cert)
			continue
		}
		expiration, err := r.FindExpirationOfCertificate(ctx, certData)
		if err != nil {
			logf.FromContext(ctx).Error(err, "Failed to find certificate expiration", "name", cert.Name, "namespace", cert.Namespace)
			cert.Message = fmt.Sprintf("Failed to find certificate expiration for %s in secret %s in namespace %s: %v", cert.CaCert, cert.Name, cert.Namespace, err)
			CertList = append(CertList, cert)
			continue
		}
		cert.Status, err = r.CheckIfValidCertificate(ctx, expiration, instance)
		if err != nil {
			logf.FromContext(ctx).Error(err, "Failed to check if certificate is valid", "name", cert.Name, "namespace", cert.Namespace)
			cert.Message = fmt.Sprintf("Failed to check if certificate %s in secret %s in namespace %s is valid: %v", cert.CaCert, cert.Name, cert.Namespace, err)
			CertList = append(CertList, cert)
			continue
		}
		cert.Message = fmt.Sprintf("Certificate %s in secret %s in namespace %s expires at %s", cert.CaCert, cert.Name, cert.Namespace, expiration)
		CertList = append(CertList, cert)

	}

	logf.FromContext(ctx).Info("Fetched certificates expiry details", "certificates", CertList)
	return CertList
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
func (r *OCPCertificateTrackerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling OCPCertificateTracker", "name", req.Name, "namespace", req.Namespace)

	instance, err := r.FetchInstance(ctx, req.Name, req.Namespace)
	if err != nil {
		log.Error(err, "Failed to fetch OCPCertificateTracker")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info("Fetched OCPCertificateTracker", "name", instance.Name, "namespace", instance.Namespace)
	secrets := r.ReadSecrets(ctx, instance)

	certList := r.UpdateExpiryStatus(ctx, secrets, instance)
	r.CreateObjectStatus(ctx, instance, certList)
	err = r.UpdateObjectStatus(ctx, instance)
	if err != nil {
		log.Error(err, "Failed to update OCPCertificateTracker status")
		return ctrl.Result{}, err
	}

	aboutToExpireCerts := r.GetAboutToExpireCertificatesApplication(ctx, certList)
	if len(aboutToExpireCerts) > 0 {
		log.Info("Certificates about to expire", "certificates", aboutToExpireCerts)
	} else {
		log.Info("No certificates about to expire")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OCPCertificateTrackerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.OCPCertificateTracker{}).
		Named("ocpcertificatetracker").
		Complete(r)
}
