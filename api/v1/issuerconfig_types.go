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

type SecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type AcmeSecret struct {
	SecretRef SecretRef `json:"secretRef"`
}

type IssuerConfigSpec struct {
	// +kubebuilder:validation:Required
	AcmeHost string `json:"acmeHost"`
	// +kubebuilder:validation:Required
	PdnsHost string `json:"pdnsHost"`
	// +kubebuilder:validation:Required
	Email string `json:"email"`
	// +kubebuilder:validation:Required
	AcmeSecret AcmeSecret `json:"acmeSecret"`
}

// IssuerConfigStatus defines the observed state of IssuerConfig.
type IssuerConfigStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// IssuerConfig is the Schema for the issuerconfigs API
type IssuerConfig struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of IssuerConfig
	// +required
	Spec IssuerConfigSpec `json:"spec"`

	// status defines the observed state of IssuerConfig
	// +optional
	Status IssuerConfigStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// IssuerConfigList contains a list of IssuerConfig
type IssuerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IssuerConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IssuerConfig{}, &IssuerConfigList{})
}
