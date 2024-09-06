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

type ExternalDownstreamsInitParameters struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The OCID of the TSIG key. A TSIG key is used to secure DNS messages (in this case, zone transfers) between two systems that both have the (shared) secret.
	TsigKeyID *string `json:"tsigKeyId,omitempty" tf:"tsig_key_id,omitempty"`
}

type ExternalDownstreamsObservation struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The OCID of the TSIG key. A TSIG key is used to secure DNS messages (in this case, zone transfers) between two systems that both have the (shared) secret.
	TsigKeyID *string `json:"tsigKeyId,omitempty" tf:"tsig_key_id,omitempty"`
}

type ExternalDownstreamsParameters struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	// +kubebuilder:validation:Optional
	Address *string `json:"address" tf:"address,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	// +kubebuilder:validation:Optional
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The OCID of the TSIG key. A TSIG key is used to secure DNS messages (in this case, zone transfers) between two systems that both have the (shared) secret.
	// +kubebuilder:validation:Optional
	TsigKeyID *string `json:"tsigKeyId,omitempty" tf:"tsig_key_id,omitempty"`
}

type ExternalMastersInitParameters struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The OCID of the TSIG key. A TSIG key is used to secure DNS messages (in this case, zone transfers) between two systems that both have the (shared) secret.
	TsigKeyID *string `json:"tsigKeyId,omitempty" tf:"tsig_key_id,omitempty"`
}

type ExternalMastersObservation struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The OCID of the TSIG key. A TSIG key is used to secure DNS messages (in this case, zone transfers) between two systems that both have the (shared) secret.
	TsigKeyID *string `json:"tsigKeyId,omitempty" tf:"tsig_key_id,omitempty"`
}

type ExternalMastersParameters struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	// +kubebuilder:validation:Optional
	Address *string `json:"address" tf:"address,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	// +kubebuilder:validation:Optional
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The OCID of the TSIG key. A TSIG key is used to secure DNS messages (in this case, zone transfers) between two systems that both have the (shared) secret.
	// +kubebuilder:validation:Optional
	TsigKeyID *string `json:"tsigKeyId,omitempty" tf:"tsig_key_id,omitempty"`
}

type NameserversInitParameters struct {
}

type NameserversObservation struct {

	// The hostname of the nameserver.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`
}

type NameserversParameters struct {
}

type ZoneInitParameters struct {

	// (Updatable) The OCID of the compartment the resource belongs to.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) External secondary servers for the zone. This field is currently not supported when zoneType is SECONDARY or scope is PRIVATE.
	ExternalDownstreams []ExternalDownstreamsInitParameters `json:"externalDownstreams,omitempty" tf:"external_downstreams,omitempty"`

	// (Updatable) External master servers for the zone. externalMasters becomes a required parameter when the zoneType value is SECONDARY.
	ExternalMasters []ExternalMastersInitParameters `json:"externalMasters,omitempty" tf:"external_masters,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The name of the zone.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// Specifies to operate only on resources that have a matching DNS scope.
	// This value will be null for zones in the global DNS and PRIVATE when creating a private zone.
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
	ViewID *string `json:"viewId,omitempty" tf:"view_id,omitempty"`

	// The type of the zone. Must be either PRIMARY or SECONDARY. SECONDARY is only supported for GLOBAL zones.
	ZoneType *string `json:"zoneType,omitempty" tf:"zone_type,omitempty"`
}

type ZoneObservation struct {

	// (Updatable) The OCID of the compartment the resource belongs to.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) External secondary servers for the zone. This field is currently not supported when zoneType is SECONDARY or scope is PRIVATE.
	ExternalDownstreams []ExternalDownstreamsObservation `json:"externalDownstreams,omitempty" tf:"external_downstreams,omitempty"`

	// (Updatable) External master servers for the zone. externalMasters becomes a required parameter when the zoneType value is SECONDARY.
	ExternalMasters []ExternalMastersObservation `json:"externalMasters,omitempty" tf:"external_masters,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The OCID of the zone.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
	IsProtected *bool `json:"isProtected,omitempty" tf:"is_protected,omitempty"`

	// The name of the zone.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The authoritative nameservers for the zone.
	Nameservers []NameserversObservation `json:"nameservers,omitempty" tf:"nameservers,omitempty"`

	// Specifies to operate only on resources that have a matching DNS scope.
	// This value will be null for zones in the global DNS and PRIVATE when creating a private zone.
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// The canonical absolute URL of the resource.
	Self *string `json:"self,omitempty" tf:"self,omitempty"`

	// The current serial of the zone. As seen in the zone's SOA record.
	Serial *float64 `json:"serial,omitempty" tf:"serial,omitempty"`

	// The current state of the zone resource.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
	Version *string `json:"version,omitempty" tf:"version,omitempty"`

	// The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
	ViewID *string `json:"viewId,omitempty" tf:"view_id,omitempty"`

	// The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
	ZoneTransferServers []ZoneTransferServersObservation `json:"zoneTransferServers,omitempty" tf:"zone_transfer_servers,omitempty"`

	// The type of the zone. Must be either PRIMARY or SECONDARY. SECONDARY is only supported for GLOBAL zones.
	ZoneType *string `json:"zoneType,omitempty" tf:"zone_type,omitempty"`
}

type ZoneParameters struct {

	// (Updatable) The OCID of the compartment the resource belongs to.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) External secondary servers for the zone. This field is currently not supported when zoneType is SECONDARY or scope is PRIVATE.
	// +kubebuilder:validation:Optional
	ExternalDownstreams []ExternalDownstreamsParameters `json:"externalDownstreams,omitempty" tf:"external_downstreams,omitempty"`

	// (Updatable) External master servers for the zone. externalMasters becomes a required parameter when the zoneType value is SECONDARY.
	// +kubebuilder:validation:Optional
	ExternalMasters []ExternalMastersParameters `json:"externalMasters,omitempty" tf:"external_masters,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The name of the zone.
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// Specifies to operate only on resources that have a matching DNS scope.
	// This value will be null for zones in the global DNS and PRIVATE when creating a private zone.
	// +kubebuilder:validation:Optional
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
	// +kubebuilder:validation:Optional
	ViewID *string `json:"viewId,omitempty" tf:"view_id,omitempty"`

	// The type of the zone. Must be either PRIMARY or SECONDARY. SECONDARY is only supported for GLOBAL zones.
	// +kubebuilder:validation:Optional
	ZoneType *string `json:"zoneType,omitempty" tf:"zone_type,omitempty"`
}

type ZoneTransferServersInitParameters struct {
}

type ZoneTransferServersObservation struct {

	// (Updatable) The server's IP address (IPv4 or IPv6).
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// A Boolean flag indicating whether or not the server is a zone data transfer destination.
	IsTransferDestination *bool `json:"isTransferDestination,omitempty" tf:"is_transfer_destination,omitempty"`

	// A Boolean flag indicating whether or not the server is a zone data transfer source.
	IsTransferSource *bool `json:"isTransferSource,omitempty" tf:"is_transfer_source,omitempty"`

	// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`
}

type ZoneTransferServersParameters struct {
}

// ZoneSpec defines the desired state of Zone
type ZoneSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ZoneParameters `json:"forProvider"`
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
	InitProvider ZoneInitParameters `json:"initProvider,omitempty"`
}

// ZoneStatus defines the observed state of Zone.
type ZoneStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ZoneObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Zone is the Schema for the Zones API. Provides the Zone resource in Oracle Cloud Infrastructure DNS service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type Zone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.compartmentId) || (has(self.initProvider) && has(self.initProvider.compartmentId))",message="spec.forProvider.compartmentId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneType) || (has(self.initProvider) && has(self.initProvider.zoneType))",message="spec.forProvider.zoneType is a required parameter"
	Spec   ZoneSpec   `json:"spec"`
	Status ZoneStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ZoneList contains a list of Zones
type ZoneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Zone `json:"items"`
}

// Repository type metadata.
var (
	Zone_Kind             = "Zone"
	Zone_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Zone_Kind}.String()
	Zone_KindAPIVersion   = Zone_Kind + "." + CRDGroupVersion.String()
	Zone_GroupVersionKind = CRDGroupVersion.WithKind(Zone_Kind)
)

func init() {
	SchemeBuilder.Register(&Zone{}, &ZoneList{})
}
