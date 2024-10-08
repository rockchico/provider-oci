// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by upjet. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type DefaultRoutingPolicyInitParameters struct {

	// (Updatable) Type of the virtual service routing policy.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type DefaultRoutingPolicyObservation struct {

	// (Updatable) Type of the virtual service routing policy.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type DefaultRoutingPolicyParameters struct {

	// (Updatable) Type of the virtual service routing policy.
	// +kubebuilder:validation:Optional
	Type *string `json:"type" tf:"type,omitempty"`
}

type MeshVirtualServiceInitParameters struct {

	// (Updatable) The OCID of the compartment.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy []DefaultRoutingPolicyInitParameters `json:"defaultRoutingPolicy,omitempty" tf:"default_routing_policy,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: {"foo-namespace.bar-key": "value"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: This is my new resource
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: {"bar-key": "value"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", ".example.com", ".com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts []*string `json:"hosts,omitempty" tf:"hosts,omitempty"`

	// The OCID of the service mesh in which this virtual service is created.
	MeshID *string `json:"meshId,omitempty" tf:"mesh_id,omitempty"`

	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls []MeshVirtualServiceMtlsInitParameters `json:"mtls,omitempty" tf:"mtls,omitempty"`

	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: My unique resource name
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

type MeshVirtualServiceMtlsInitParameters struct {

	// (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
	MaximumValidity *float64 `json:"maximumValidity,omitempty" tf:"maximum_validity,omitempty"`

	// (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`
}

type MeshVirtualServiceMtlsObservation struct {

	// The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
	CertificateID *string `json:"certificateId,omitempty" tf:"certificate_id,omitempty"`

	// (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
	MaximumValidity *float64 `json:"maximumValidity,omitempty" tf:"maximum_validity,omitempty"`

	// (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`
}

type MeshVirtualServiceMtlsParameters struct {

	// (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
	// +kubebuilder:validation:Optional
	MaximumValidity *float64 `json:"maximumValidity,omitempty" tf:"maximum_validity,omitempty"`

	// (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
	// +kubebuilder:validation:Optional
	Mode *string `json:"mode" tf:"mode,omitempty"`
}

type MeshVirtualServiceObservation struct {

	// (Updatable) The OCID of the compartment.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy []DefaultRoutingPolicyObservation `json:"defaultRoutingPolicy,omitempty" tf:"default_routing_policy,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: {"foo-namespace.bar-key": "value"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: This is my new resource
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: {"bar-key": "value"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", ".example.com", ".com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts []*string `json:"hosts,omitempty" tf:"hosts,omitempty"`

	// Unique identifier that is immutable on creation.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `json:"lifecycleDetails,omitempty" tf:"lifecycle_details,omitempty"`

	// The OCID of the service mesh in which this virtual service is created.
	MeshID *string `json:"meshId,omitempty" tf:"mesh_id,omitempty"`

	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls []MeshVirtualServiceMtlsObservation `json:"mtls,omitempty" tf:"mtls,omitempty"`

	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: My unique resource name
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The current state of the Resource.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: {"orcl-cloud.free-tier-retained": "true"}
	// +mapType=granular
	SystemTags map[string]*string `json:"systemTags,omitempty" tf:"system_tags,omitempty"`

	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated *string `json:"timeUpdated,omitempty" tf:"time_updated,omitempty"`
}

type MeshVirtualServiceParameters struct {

	// (Updatable) The OCID of the compartment.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Routing policy for the virtual service.
	// +kubebuilder:validation:Optional
	DefaultRoutingPolicy []DefaultRoutingPolicyParameters `json:"defaultRoutingPolicy,omitempty" tf:"default_routing_policy,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: {"foo-namespace.bar-key": "value"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: This is my new resource
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: {"bar-key": "value"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", ".example.com", ".com". Can be omitted if the virtual service will only have TCP virtual deployments.
	// +kubebuilder:validation:Optional
	Hosts []*string `json:"hosts,omitempty" tf:"hosts,omitempty"`

	// The OCID of the service mesh in which this virtual service is created.
	// +kubebuilder:validation:Optional
	MeshID *string `json:"meshId,omitempty" tf:"mesh_id,omitempty"`

	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	// +kubebuilder:validation:Optional
	Mtls []MeshVirtualServiceMtlsParameters `json:"mtls,omitempty" tf:"mtls,omitempty"`

	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: My unique resource name
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

// MeshVirtualServiceSpec defines the desired state of MeshVirtualService
type MeshVirtualServiceSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     MeshVirtualServiceParameters `json:"forProvider"`
	// THIS IS A BETA FIELD. It will be honored
	// unless the Management Policies feature flag is disabled.
	// InitProvider holds the same fields as ForProvider, with the exception
	// of Identifier and other resource reference fields. The fields that are
	// in InitProvider are merged into ForProvider when the resource is created.
	// The same fields are also added to the terraform ignore_changes hook, to
	// avoid updating them after creation. This is useful for fields that are
	// required on creation, but we do not desire to update them after creation,
	// for example because of an external controller is managing them, like an
	// autoscaler.
	InitProvider MeshVirtualServiceInitParameters `json:"initProvider,omitempty"`
}

// MeshVirtualServiceStatus defines the observed state of MeshVirtualService.
type MeshVirtualServiceStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        MeshVirtualServiceObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// MeshVirtualService is the Schema for the MeshVirtualServices API. Provides the Virtual Service resource in Oracle Cloud Infrastructure Service Mesh service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type MeshVirtualService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.compartmentId) || (has(self.initProvider) && has(self.initProvider.compartmentId))",message="spec.forProvider.compartmentId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.meshId) || (has(self.initProvider) && has(self.initProvider.meshId))",message="spec.forProvider.meshId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	Spec   MeshVirtualServiceSpec   `json:"spec"`
	Status MeshVirtualServiceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MeshVirtualServiceList contains a list of MeshVirtualServices
type MeshVirtualServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MeshVirtualService `json:"items"`
}

// Repository type metadata.
var (
	MeshVirtualService_Kind             = "MeshVirtualService"
	MeshVirtualService_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: MeshVirtualService_Kind}.String()
	MeshVirtualService_KindAPIVersion   = MeshVirtualService_Kind + "." + CRDGroupVersion.String()
	MeshVirtualService_GroupVersionKind = CRDGroupVersion.WithKind(MeshVirtualService_Kind)
)

func init() {
	SchemeBuilder.Register(&MeshVirtualService{}, &MeshVirtualServiceList{})
}
