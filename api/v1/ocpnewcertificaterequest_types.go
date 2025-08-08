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

type CertificateRequest struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	GitPath string   `json:"gitPath,omitempty"`
}

type CertificateRequestStatus struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	Message         string `json:"message"`
	SecretName      string `json:"secretName"`
	SecretNamespace string `json:"secretNamespace"`
}

// OCPNewCertificateRequestSpec defines the desired state of OCPNewCertificateRequest
type OCPNewCertificateRequestSpec struct {
	Certificates []CertificateRequest `json:"certificates"`
}

// OCPNewCertificateRequestStatus defines the observed state of OCPNewCertificateRequest.
type OCPNewCertificateRequestStatus struct {
	Certificates []CertificateRequestStatus `json:"certificates"`
	GitMR        string                     `json:"gitMR"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OCPNewCertificateRequest is the Schema for the ocpnewcertificaterequests API
type OCPNewCertificateRequest struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of OCPNewCertificateRequest
	// +required
	Spec OCPNewCertificateRequestSpec `json:"spec"`

	// status defines the observed state of OCPNewCertificateRequest
	// +optional
	Status OCPNewCertificateRequestStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// OCPNewCertificateRequestList contains a list of OCPNewCertificateRequest
type OCPNewCertificateRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCPNewCertificateRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OCPNewCertificateRequest{}, &OCPNewCertificateRequestList{})
}
