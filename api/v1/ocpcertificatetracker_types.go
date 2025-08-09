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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CertificatesStruct struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	// +kubebuilder:default:="ca.crt"
	CaCert  string `json:"caCert,omitempty"`
	GitPath string `json:"gitPath"`
}

type CertificatesStatusStruct struct {
	Name        string      `json:"name"`
	Namespace   string      `json:"namespace"`
	CaCert      string      `json:"caCert,omitempty"`
	LastChecked metav1.Time `json:"lastChecked,omitempty"`
	Expiry      string      `json:"expiry,omitempty"`
	Status      string      `json:"status,omitempty"`
	Message     string      `json:"message,omitempty"`
	GitPath     string      `json:"gitPath,omitempty"`
}

// OCPCertificateTrackerSpec defines the desired state of OCPCertificateTracker
type OCPCertificateTrackerSpec struct {
	Certificates []CertificatesStruct `json:"certificates"`

	// +kubebuilder:default:="720h"
	ExpirationThreshold string `json:"expirationThreshold"`
}

// OCPCertificateTrackerStatus defines the observed state of OCPCertificateTracker.
type OCPCertificateTrackerStatus struct {
	Certificates []CertificatesStatusStruct `json:"certificates"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OCPCertificateTracker is the Schema for the ocpcertificatetrackers API
type OCPCertificateTracker struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of OCPCertificateTracker
	// +required
	Spec OCPCertificateTrackerSpec `json:"spec"`

	// status defines the observed state of OCPCertificateTracker
	// +optional
	Status OCPCertificateTrackerStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// OCPCertificateTrackerList contains a list of OCPCertificateTracker
type OCPCertificateTrackerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCPCertificateTracker `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OCPCertificateTracker{}, &OCPCertificateTrackerList{})
}
