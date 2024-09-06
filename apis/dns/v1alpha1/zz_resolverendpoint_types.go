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

type ResolverEndpointInitParameters struct {

	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType *string `json:"endpointType,omitempty" tf:"endpoint_type,omitempty"`

	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress *string `json:"forwardingAddress,omitempty" tf:"forwarding_address,omitempty"`

	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding *bool `json:"isForwarding,omitempty" tf:"is_forwarding,omitempty"`

	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening *bool `json:"isListening,omitempty" tf:"is_listening,omitempty"`

	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress *string `json:"listeningAddress,omitempty" tf:"listening_address,omitempty"`

	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	// +listType=set
	NsgIds []*string `json:"nsgIds,omitempty" tf:"nsg_ids,omitempty"`

	// The OCID of the target resolver.
	ResolverID *string `json:"resolverId,omitempty" tf:"resolver_id,omitempty"`

	// Value must be PRIVATE when creating private name resolver endpoints.
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetID *string `json:"subnetId,omitempty" tf:"subnet_id,omitempty"`
}

type ResolverEndpointObservation struct {

	// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType *string `json:"endpointType,omitempty" tf:"endpoint_type,omitempty"`

	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress *string `json:"forwardingAddress,omitempty" tf:"forwarding_address,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding *bool `json:"isForwarding,omitempty" tf:"is_forwarding,omitempty"`

	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening *bool `json:"isListening,omitempty" tf:"is_listening,omitempty"`

	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress *string `json:"listeningAddress,omitempty" tf:"listening_address,omitempty"`

	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	// +listType=set
	NsgIds []*string `json:"nsgIds,omitempty" tf:"nsg_ids,omitempty"`

	// The OCID of the target resolver.
	ResolverID *string `json:"resolverId,omitempty" tf:"resolver_id,omitempty"`

	// Value must be PRIVATE when creating private name resolver endpoints.
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// The canonical absolute URL of the resource.
	Self *string `json:"self,omitempty" tf:"self,omitempty"`

	// The current state of the resource.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetID *string `json:"subnetId,omitempty" tf:"subnet_id,omitempty"`

	// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdated *string `json:"timeUpdated,omitempty" tf:"time_updated,omitempty"`
}

type ResolverEndpointParameters struct {

	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	// +kubebuilder:validation:Optional
	EndpointType *string `json:"endpointType,omitempty" tf:"endpoint_type,omitempty"`

	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	// +kubebuilder:validation:Optional
	ForwardingAddress *string `json:"forwardingAddress,omitempty" tf:"forwarding_address,omitempty"`

	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	// +kubebuilder:validation:Optional
	IsForwarding *bool `json:"isForwarding,omitempty" tf:"is_forwarding,omitempty"`

	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	// +kubebuilder:validation:Optional
	IsListening *bool `json:"isListening,omitempty" tf:"is_listening,omitempty"`

	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	// +kubebuilder:validation:Optional
	ListeningAddress *string `json:"listeningAddress,omitempty" tf:"listening_address,omitempty"`

	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	// +kubebuilder:validation:Optional
	// +listType=set
	NsgIds []*string `json:"nsgIds,omitempty" tf:"nsg_ids,omitempty"`

	// The OCID of the target resolver.
	// +kubebuilder:validation:Optional
	ResolverID *string `json:"resolverId,omitempty" tf:"resolver_id,omitempty"`

	// Value must be PRIVATE when creating private name resolver endpoints.
	// +kubebuilder:validation:Optional
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	// +kubebuilder:validation:Optional
	SubnetID *string `json:"subnetId,omitempty" tf:"subnet_id,omitempty"`
}

// ResolverEndpointSpec defines the desired state of ResolverEndpoint
type ResolverEndpointSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ResolverEndpointParameters `json:"forProvider"`
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
	InitProvider ResolverEndpointInitParameters `json:"initProvider,omitempty"`
}

// ResolverEndpointStatus defines the observed state of ResolverEndpoint.
type ResolverEndpointStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ResolverEndpointObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// ResolverEndpoint is the Schema for the ResolverEndpoints API. Provides the Resolver Endpoint resource in Oracle Cloud Infrastructure DNS service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type ResolverEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.isForwarding) || (has(self.initProvider) && has(self.initProvider.isForwarding))",message="spec.forProvider.isForwarding is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.isListening) || (has(self.initProvider) && has(self.initProvider.isListening))",message="spec.forProvider.isListening is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.resolverId) || (has(self.initProvider) && has(self.initProvider.resolverId))",message="spec.forProvider.resolverId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.subnetId) || (has(self.initProvider) && has(self.initProvider.subnetId))",message="spec.forProvider.subnetId is a required parameter"
	Spec   ResolverEndpointSpec   `json:"spec"`
	Status ResolverEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ResolverEndpointList contains a list of ResolverEndpoints
type ResolverEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResolverEndpoint `json:"items"`
}

// Repository type metadata.
var (
	ResolverEndpoint_Kind             = "ResolverEndpoint"
	ResolverEndpoint_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ResolverEndpoint_Kind}.String()
	ResolverEndpoint_KindAPIVersion   = ResolverEndpoint_Kind + "." + CRDGroupVersion.String()
	ResolverEndpoint_GroupVersionKind = CRDGroupVersion.WithKind(ResolverEndpoint_Kind)
)

func init() {
	SchemeBuilder.Register(&ResolverEndpoint{}, &ResolverEndpointList{})
}
