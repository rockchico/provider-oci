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

type DrgAllAttachmentsInitParameters struct {
}

type DrgAllAttachmentsObservation struct {

	// The Oracle-assigned ID of the DRG attachment
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type DrgAllAttachmentsParameters struct {
}

type DrgAttachmentsListInitParameters struct {

	// The type for the network resource attached to the DRG.
	AttachmentType *string `json:"attachmentType,omitempty" tf:"attachment_type,omitempty"`

	// The OCID of the DRG.
	DrgID *string `json:"drgId,omitempty" tf:"drg_id,omitempty"`

	// Whether the DRG attachment lives in a different tenancy than the DRG.
	IsCrossTenancy *bool `json:"isCrossTenancy,omitempty" tf:"is_cross_tenancy,omitempty"`
}

type DrgAttachmentsListObservation struct {

	// The type for the network resource attached to the DRG.
	AttachmentType *string `json:"attachmentType,omitempty" tf:"attachment_type,omitempty"`

	// The list of drg_attachments.
	DrgAllAttachments []DrgAllAttachmentsObservation `json:"drgAllAttachments,omitempty" tf:"drg_all_attachments,omitempty"`

	// The OCID of the DRG.
	DrgID *string `json:"drgId,omitempty" tf:"drg_id,omitempty"`

	// The Oracle-assigned ID of the DRG attachment
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Whether the DRG attachment lives in a different tenancy than the DRG.
	IsCrossTenancy *bool `json:"isCrossTenancy,omitempty" tf:"is_cross_tenancy,omitempty"`
}

type DrgAttachmentsListParameters struct {

	// The type for the network resource attached to the DRG.
	// +kubebuilder:validation:Optional
	AttachmentType *string `json:"attachmentType,omitempty" tf:"attachment_type,omitempty"`

	// The OCID of the DRG.
	// +kubebuilder:validation:Optional
	DrgID *string `json:"drgId,omitempty" tf:"drg_id,omitempty"`

	// Whether the DRG attachment lives in a different tenancy than the DRG.
	// +kubebuilder:validation:Optional
	IsCrossTenancy *bool `json:"isCrossTenancy,omitempty" tf:"is_cross_tenancy,omitempty"`
}

// DrgAttachmentsListSpec defines the desired state of DrgAttachmentsList
type DrgAttachmentsListSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     DrgAttachmentsListParameters `json:"forProvider"`
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
	InitProvider DrgAttachmentsListInitParameters `json:"initProvider,omitempty"`
}

// DrgAttachmentsListStatus defines the observed state of DrgAttachmentsList.
type DrgAttachmentsListStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        DrgAttachmentsListObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// DrgAttachmentsList is the Schema for the DrgAttachmentsLists API. Provides the Drg Attachments List resource in Oracle Cloud Infrastructure Core service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type DrgAttachmentsList struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.drgId) || (has(self.initProvider) && has(self.initProvider.drgId))",message="spec.forProvider.drgId is a required parameter"
	Spec   DrgAttachmentsListSpec   `json:"spec"`
	Status DrgAttachmentsListStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DrgAttachmentsListList contains a list of DrgAttachmentsLists
type DrgAttachmentsListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DrgAttachmentsList `json:"items"`
}

// Repository type metadata.
var (
	DrgAttachmentsList_Kind             = "DrgAttachmentsList"
	DrgAttachmentsList_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DrgAttachmentsList_Kind}.String()
	DrgAttachmentsList_KindAPIVersion   = DrgAttachmentsList_Kind + "." + CRDGroupVersion.String()
	DrgAttachmentsList_GroupVersionKind = CRDGroupVersion.WithKind(DrgAttachmentsList_Kind)
)

func init() {
	SchemeBuilder.Register(&DrgAttachmentsList{}, &DrgAttachmentsListList{})
}
