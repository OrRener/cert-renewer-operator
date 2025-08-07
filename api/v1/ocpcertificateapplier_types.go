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

type TargetSecret struct {
	Name        string   `json:"name"`
	Application string   `json:"application"`
	Dnses       []string `json:"dnses"`
	GitPath     string   `json:"gitPath"`
}

type CertificateStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`  // e.g. "Ready", "NotReady", "Failed"
	Message string `json:"message"` // Additional information about the certificate status
}

// OCPCertificateApplierSpec defines the desired state of OCPCertificateApplier
type OCPCertificateApplierSpec struct {
	CertificatesToCreate []TargetSecret `json:"certificatesToCreate"`
}

// OCPCertificateApplierStatus defines the observed state of OCPCertificateApplier.
type OCPCertificateApplierStatus struct {
	Certificates []CertificateStatus `json:"certificates"`
	GitPR        string              `json:"gitPR,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OCPCertificateApplier is the Schema for the ocpcertificateappliers API
type OCPCertificateApplier struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of OCPCertificateApplier
	// +required
	Spec OCPCertificateApplierSpec `json:"spec"`

	// status defines the observed state of OCPCertificateApplier
	// +optional
	Status OCPCertificateApplierStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// OCPCertificateApplierList contains a list of OCPCertificateApplier
type OCPCertificateApplierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCPCertificateApplier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OCPCertificateApplier{}, &OCPCertificateApplierList{})
}
