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

type StreamInitParameters struct {

	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The name of the stream. Avoid entering confidential information.  Example: TelemetryEvents
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The number of partitions in the stream.
	Partitions *float64 `json:"partitions,omitempty" tf:"partitions,omitempty"`

	// The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
	RetentionInHours *float64 `json:"retentionInHours,omitempty" tf:"retention_in_hours,omitempty"`

	// (Updatable) The OCID of the stream pool that contains the stream.
	StreamPoolID *string `json:"streamPoolId,omitempty" tf:"stream_pool_id,omitempty"`
}

type StreamObservation struct {

	// (Updatable) The OCID of the compartment that contains the stream.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The OCID of the stream.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Any additional details about the current state of the stream.
	LifecycleStateDetails *string `json:"lifecycleStateDetails,omitempty" tf:"lifecycle_state_details,omitempty"`

	// The endpoint to use when creating the StreamClient to consume or publish messages in the stream. If the associated stream pool is private, the endpoint is also private and can only be accessed from inside the stream pool's associated subnet.
	MessagesEndpoint *string `json:"messagesEndpoint,omitempty" tf:"messages_endpoint,omitempty"`

	// The name of the stream. Avoid entering confidential information.  Example: TelemetryEvents
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The number of partitions in the stream.
	Partitions *float64 `json:"partitions,omitempty" tf:"partitions,omitempty"`

	// The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
	RetentionInHours *float64 `json:"retentionInHours,omitempty" tf:"retention_in_hours,omitempty"`

	// The current state of the stream.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// (Updatable) The OCID of the stream pool that contains the stream.
	StreamPoolID *string `json:"streamPoolId,omitempty" tf:"stream_pool_id,omitempty"`

	// The date and time the stream was created, expressed in in RFC 3339 timestamp format.  Example: 2018-04-20T00:00:07.405Z
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`
}

type StreamParameters struct {

	// (Updatable) The OCID of the compartment that contains the stream.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The name of the stream. Avoid entering confidential information.  Example: TelemetryEvents
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The number of partitions in the stream.
	// +kubebuilder:validation:Optional
	Partitions *float64 `json:"partitions,omitempty" tf:"partitions,omitempty"`

	// The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
	// +kubebuilder:validation:Optional
	RetentionInHours *float64 `json:"retentionInHours,omitempty" tf:"retention_in_hours,omitempty"`

	// (Updatable) The OCID of the stream pool that contains the stream.
	// +kubebuilder:validation:Optional
	StreamPoolID *string `json:"streamPoolId,omitempty" tf:"stream_pool_id,omitempty"`
}

// StreamSpec defines the desired state of Stream
type StreamSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     StreamParameters `json:"forProvider"`
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
	InitProvider StreamInitParameters `json:"initProvider,omitempty"`
}

// StreamStatus defines the observed state of Stream.
type StreamStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        StreamObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Stream is the Schema for the Streams API. Provides the Stream resource in Oracle Cloud Infrastructure Streaming service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type Stream struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.partitions) || (has(self.initProvider) && has(self.initProvider.partitions))",message="spec.forProvider.partitions is a required parameter"
	Spec   StreamSpec   `json:"spec"`
	Status StreamStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StreamList contains a list of Streams
type StreamList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Stream `json:"items"`
}

// Repository type metadata.
var (
	Stream_Kind             = "Stream"
	Stream_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Stream_Kind}.String()
	Stream_KindAPIVersion   = Stream_Kind + "." + CRDGroupVersion.String()
	Stream_GroupVersionKind = CRDGroupVersion.WithKind(Stream_Kind)
)

func init() {
	SchemeBuilder.Register(&Stream{}, &StreamList{})
}
