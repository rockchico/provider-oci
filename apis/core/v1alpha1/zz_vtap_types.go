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

type VtapInitParameters struct {

	// (Updatable) The capture filter's Oracle ID (OCID).
	CaptureFilterID *string `json:"captureFilterId,omitempty" tf:"capture_filter_id,omitempty"`

	// (Updatable) The OCID of the compartment containing the Vtap resource.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol *string `json:"encapsulationProtocol,omitempty" tf:"encapsulation_protocol,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) Used to start or stop a Vtap resource.
	IsVtapEnabled *bool `json:"isVtapEnabled,omitempty" tf:"is_vtap_enabled,omitempty"`

	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize *float64 `json:"maxPacketSize,omitempty" tf:"max_packet_size,omitempty"`

	// (Updatable) The OCID of the source point where packets are captured.
	SourceID *string `json:"sourceId,omitempty" tf:"source_id,omitempty"`

	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIP *string `json:"sourcePrivateEndpointIp,omitempty" tf:"source_private_endpoint_ip,omitempty"`

	// (Updatable) The OCID of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetID *string `json:"sourcePrivateEndpointSubnetId,omitempty" tf:"source_private_endpoint_subnet_id,omitempty"`

	// (Updatable) The source type for the VTAP.
	SourceType *string `json:"sourceType,omitempty" tf:"source_type,omitempty"`

	// (Updatable) The OCID of the destination resource where mirrored packets are sent.
	TargetID *string `json:"targetId,omitempty" tf:"target_id,omitempty"`

	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIP *string `json:"targetIp,omitempty" tf:"target_ip,omitempty"`

	// (Updatable) The target type for the VTAP.
	TargetType *string `json:"targetType,omitempty" tf:"target_type,omitempty"`

	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode *string `json:"trafficMode,omitempty" tf:"traffic_mode,omitempty"`

	// The OCID of the VCN containing the Vtap resource.
	VcnID *string `json:"vcnId,omitempty" tf:"vcn_id,omitempty"`

	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	VxlanNetworkIdentifier *string `json:"vxlanNetworkIdentifier,omitempty" tf:"vxlan_network_identifier,omitempty"`
}

type VtapObservation struct {

	// (Updatable) The capture filter's Oracle ID (OCID).
	CaptureFilterID *string `json:"captureFilterId,omitempty" tf:"capture_filter_id,omitempty"`

	// (Updatable) The OCID of the compartment containing the Vtap resource.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol *string `json:"encapsulationProtocol,omitempty" tf:"encapsulation_protocol,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The VTAP's Oracle ID (OCID).
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Updatable) Used to start or stop a Vtap resource.
	IsVtapEnabled *bool `json:"isVtapEnabled,omitempty" tf:"is_vtap_enabled,omitempty"`

	// The VTAP's current running state.
	LifecycleStateDetails *string `json:"lifecycleStateDetails,omitempty" tf:"lifecycle_state_details,omitempty"`

	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize *float64 `json:"maxPacketSize,omitempty" tf:"max_packet_size,omitempty"`

	// (Updatable) The OCID of the source point where packets are captured.
	SourceID *string `json:"sourceId,omitempty" tf:"source_id,omitempty"`

	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIP *string `json:"sourcePrivateEndpointIp,omitempty" tf:"source_private_endpoint_ip,omitempty"`

	// (Updatable) The OCID of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetID *string `json:"sourcePrivateEndpointSubnetId,omitempty" tf:"source_private_endpoint_subnet_id,omitempty"`

	// (Updatable) The source type for the VTAP.
	SourceType *string `json:"sourceType,omitempty" tf:"source_type,omitempty"`

	// The VTAP's administrative lifecycle state.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// (Updatable) The OCID of the destination resource where mirrored packets are sent.
	TargetID *string `json:"targetId,omitempty" tf:"target_id,omitempty"`

	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIP *string `json:"targetIp,omitempty" tf:"target_ip,omitempty"`

	// (Updatable) The target type for the VTAP.
	TargetType *string `json:"targetType,omitempty" tf:"target_type,omitempty"`

	// The date and time the VTAP was created, in the format defined by RFC3339.  Example: 2020-08-25T21:10:29.600Z
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode *string `json:"trafficMode,omitempty" tf:"traffic_mode,omitempty"`

	// The OCID of the VCN containing the Vtap resource.
	VcnID *string `json:"vcnId,omitempty" tf:"vcn_id,omitempty"`

	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	VxlanNetworkIdentifier *string `json:"vxlanNetworkIdentifier,omitempty" tf:"vxlan_network_identifier,omitempty"`
}

type VtapParameters struct {

	// (Updatable) The capture filter's Oracle ID (OCID).
	// +kubebuilder:validation:Optional
	CaptureFilterID *string `json:"captureFilterId,omitempty" tf:"capture_filter_id,omitempty"`

	// (Updatable) The OCID of the compartment containing the Vtap resource.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	// +kubebuilder:validation:Optional
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	// +kubebuilder:validation:Optional
	EncapsulationProtocol *string `json:"encapsulationProtocol,omitempty" tf:"encapsulation_protocol,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) Used to start or stop a Vtap resource.
	// +kubebuilder:validation:Optional
	IsVtapEnabled *bool `json:"isVtapEnabled,omitempty" tf:"is_vtap_enabled,omitempty"`

	// (Updatable) The maximum size of the packets to be included in the filter.
	// +kubebuilder:validation:Optional
	MaxPacketSize *float64 `json:"maxPacketSize,omitempty" tf:"max_packet_size,omitempty"`

	// (Updatable) The OCID of the source point where packets are captured.
	// +kubebuilder:validation:Optional
	SourceID *string `json:"sourceId,omitempty" tf:"source_id,omitempty"`

	// (Updatable) The IP Address of the source private endpoint.
	// +kubebuilder:validation:Optional
	SourcePrivateEndpointIP *string `json:"sourcePrivateEndpointIp,omitempty" tf:"source_private_endpoint_ip,omitempty"`

	// (Updatable) The OCID of the subnet that source private endpoint belongs to.
	// +kubebuilder:validation:Optional
	SourcePrivateEndpointSubnetID *string `json:"sourcePrivateEndpointSubnetId,omitempty" tf:"source_private_endpoint_subnet_id,omitempty"`

	// (Updatable) The source type for the VTAP.
	// +kubebuilder:validation:Optional
	SourceType *string `json:"sourceType,omitempty" tf:"source_type,omitempty"`

	// (Updatable) The OCID of the destination resource where mirrored packets are sent.
	// +kubebuilder:validation:Optional
	TargetID *string `json:"targetId,omitempty" tf:"target_id,omitempty"`

	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	// +kubebuilder:validation:Optional
	TargetIP *string `json:"targetIp,omitempty" tf:"target_ip,omitempty"`

	// (Updatable) The target type for the VTAP.
	// +kubebuilder:validation:Optional
	TargetType *string `json:"targetType,omitempty" tf:"target_type,omitempty"`

	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	// +kubebuilder:validation:Optional
	TrafficMode *string `json:"trafficMode,omitempty" tf:"traffic_mode,omitempty"`

	// The OCID of the VCN containing the Vtap resource.
	// +kubebuilder:validation:Optional
	VcnID *string `json:"vcnId,omitempty" tf:"vcn_id,omitempty"`

	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	// +kubebuilder:validation:Optional
	VxlanNetworkIdentifier *string `json:"vxlanNetworkIdentifier,omitempty" tf:"vxlan_network_identifier,omitempty"`
}

// VtapSpec defines the desired state of Vtap
type VtapSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     VtapParameters `json:"forProvider"`
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
	InitProvider VtapInitParameters `json:"initProvider,omitempty"`
}

// VtapStatus defines the observed state of Vtap.
type VtapStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        VtapObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Vtap is the Schema for the Vtaps API. Provides the Vtap resource in Oracle Cloud Infrastructure Core service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type Vtap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.captureFilterId) || (has(self.initProvider) && has(self.initProvider.captureFilterId))",message="spec.forProvider.captureFilterId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.compartmentId) || (has(self.initProvider) && has(self.initProvider.compartmentId))",message="spec.forProvider.compartmentId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.sourceId) || (has(self.initProvider) && has(self.initProvider.sourceId))",message="spec.forProvider.sourceId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.vcnId) || (has(self.initProvider) && has(self.initProvider.vcnId))",message="spec.forProvider.vcnId is a required parameter"
	Spec   VtapSpec   `json:"spec"`
	Status VtapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VtapList contains a list of Vtaps
type VtapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Vtap `json:"items"`
}

// Repository type metadata.
var (
	Vtap_Kind             = "Vtap"
	Vtap_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Vtap_Kind}.String()
	Vtap_KindAPIVersion   = Vtap_Kind + "." + CRDGroupVersion.String()
	Vtap_GroupVersionKind = CRDGroupVersion.WithKind(Vtap_Kind)
)

func init() {
	SchemeBuilder.Register(&Vtap{}, &VtapList{})
}
