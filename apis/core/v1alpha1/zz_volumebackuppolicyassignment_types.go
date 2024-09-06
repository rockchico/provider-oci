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

type VolumeBackupPolicyAssignmentInitParameters struct {

	// The OCID of the volume or volume group to assign the policy to.
	AssetID *string `json:"assetId,omitempty" tf:"asset_id,omitempty"`

	// The OCID of the volume backup policy to assign to the volume.
	PolicyID *string `json:"policyId,omitempty" tf:"policy_id,omitempty"`
}

type VolumeBackupPolicyAssignmentObservation struct {

	// The OCID of the volume or volume group to assign the policy to.
	AssetID *string `json:"assetId,omitempty" tf:"asset_id,omitempty"`

	// The OCID of the volume backup policy assignment.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The OCID of the volume backup policy to assign to the volume.
	PolicyID *string `json:"policyId,omitempty" tf:"policy_id,omitempty"`

	// The date and time the volume backup policy was assigned to the volume. The format is defined by RFC3339.
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`
}

type VolumeBackupPolicyAssignmentParameters struct {

	// The OCID of the volume or volume group to assign the policy to.
	// +kubebuilder:validation:Optional
	AssetID *string `json:"assetId,omitempty" tf:"asset_id,omitempty"`

	// The OCID of the volume backup policy to assign to the volume.
	// +kubebuilder:validation:Optional
	PolicyID *string `json:"policyId,omitempty" tf:"policy_id,omitempty"`
}

// VolumeBackupPolicyAssignmentSpec defines the desired state of VolumeBackupPolicyAssignment
type VolumeBackupPolicyAssignmentSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     VolumeBackupPolicyAssignmentParameters `json:"forProvider"`
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
	InitProvider VolumeBackupPolicyAssignmentInitParameters `json:"initProvider,omitempty"`
}

// VolumeBackupPolicyAssignmentStatus defines the observed state of VolumeBackupPolicyAssignment.
type VolumeBackupPolicyAssignmentStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        VolumeBackupPolicyAssignmentObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// VolumeBackupPolicyAssignment is the Schema for the VolumeBackupPolicyAssignments API. Provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type VolumeBackupPolicyAssignment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.assetId) || (has(self.initProvider) && has(self.initProvider.assetId))",message="spec.forProvider.assetId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.policyId) || (has(self.initProvider) && has(self.initProvider.policyId))",message="spec.forProvider.policyId is a required parameter"
	Spec   VolumeBackupPolicyAssignmentSpec   `json:"spec"`
	Status VolumeBackupPolicyAssignmentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VolumeBackupPolicyAssignmentList contains a list of VolumeBackupPolicyAssignments
type VolumeBackupPolicyAssignmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VolumeBackupPolicyAssignment `json:"items"`
}

// Repository type metadata.
var (
	VolumeBackupPolicyAssignment_Kind             = "VolumeBackupPolicyAssignment"
	VolumeBackupPolicyAssignment_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: VolumeBackupPolicyAssignment_Kind}.String()
	VolumeBackupPolicyAssignment_KindAPIVersion   = VolumeBackupPolicyAssignment_Kind + "." + CRDGroupVersion.String()
	VolumeBackupPolicyAssignment_GroupVersionKind = CRDGroupVersion.WithKind(VolumeBackupPolicyAssignment_Kind)
)

func init() {
	SchemeBuilder.Register(&VolumeBackupPolicyAssignment{}, &VolumeBackupPolicyAssignmentList{})
}
