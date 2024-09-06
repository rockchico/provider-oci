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

type LogGroupInitParameters struct {

	// (Updatable) The OCID of the compartment that the resource belongs to.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Description for this resource.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags. Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`
}

type LogGroupObservation struct {

	// (Updatable) The OCID of the compartment that the resource belongs to.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Description for this resource.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags. Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The OCID of the resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The log group object state.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// Time the resource was created.
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// Time the resource was last modified.
	TimeLastModified *string `json:"timeLastModified,omitempty" tf:"time_last_modified,omitempty"`
}

type LogGroupParameters struct {

	// (Updatable) The OCID of the compartment that the resource belongs to.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Description for this resource.
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	// +kubebuilder:validation:Optional
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags. Example: {"Department": "Finance"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`
}

// LogGroupSpec defines the desired state of LogGroup
type LogGroupSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     LogGroupParameters `json:"forProvider"`
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
	InitProvider LogGroupInitParameters `json:"initProvider,omitempty"`
}

// LogGroupStatus defines the observed state of LogGroup.
type LogGroupStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        LogGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LogGroup is the Schema for the LogGroups API. Provides the Log Group resource in Oracle Cloud Infrastructure Logging service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type LogGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.compartmentId) || (has(self.initProvider) && has(self.initProvider.compartmentId))",message="spec.forProvider.compartmentId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.displayName) || (has(self.initProvider) && has(self.initProvider.displayName))",message="spec.forProvider.displayName is a required parameter"
	Spec   LogGroupSpec   `json:"spec"`
	Status LogGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LogGroupList contains a list of LogGroups
type LogGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogGroup `json:"items"`
}

// Repository type metadata.
var (
	LogGroup_Kind             = "LogGroup"
	LogGroup_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: LogGroup_Kind}.String()
	LogGroup_KindAPIVersion   = LogGroup_Kind + "." + CRDGroupVersion.String()
	LogGroup_GroupVersionKind = CRDGroupVersion.WithKind(LogGroup_Kind)
)

func init() {
	SchemeBuilder.Register(&LogGroup{}, &LogGroupList{})
}
