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

type StorageExportSetInitParameters struct {

	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: My export set
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Controls the maximum tbytes, fbytes, and abytes, values reported by NFS FSSTAT calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The tbytes value reported by FSSTAT will be maxFsStatBytes. The value of fbytes and abytes will be maxFsStatBytes minus the metered size of the file system. If the metered size is larger than maxFsStatBytes, then fbytes and abytes will both be '0'.
	MaxFsStatBytes *string `json:"maxFsStatBytes,omitempty" tf:"max_fs_stat_bytes,omitempty"`

	// (Updatable) Controls the maximum tfiles, ffiles, and afiles values reported by NFS FSSTAT calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The tfiles value reported by FSSTAT will be maxFsStatFiles. The value of ffiles and afiles will be maxFsStatFiles minus the metered size of the file system. If the metered size is larger than maxFsStatFiles, then ffiles and afiles will both be '0'.
	MaxFsStatFiles *string `json:"maxFsStatFiles,omitempty" tf:"max_fs_stat_files,omitempty"`

	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetID *string `json:"mountTargetId,omitempty" tf:"mount_target_id,omitempty"`
}

type StorageExportSetObservation struct {

	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: Uocm:PHX-AD-1
	AvailabilityDomain *string `json:"availabilityDomain,omitempty" tf:"availability_domain,omitempty"`

	// The OCID of the compartment that contains the export set.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: My export set
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// The OCID of the export set.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Updatable) Controls the maximum tbytes, fbytes, and abytes, values reported by NFS FSSTAT calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The tbytes value reported by FSSTAT will be maxFsStatBytes. The value of fbytes and abytes will be maxFsStatBytes minus the metered size of the file system. If the metered size is larger than maxFsStatBytes, then fbytes and abytes will both be '0'.
	MaxFsStatBytes *string `json:"maxFsStatBytes,omitempty" tf:"max_fs_stat_bytes,omitempty"`

	// (Updatable) Controls the maximum tfiles, ffiles, and afiles values reported by NFS FSSTAT calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The tfiles value reported by FSSTAT will be maxFsStatFiles. The value of ffiles and afiles will be maxFsStatFiles minus the metered size of the file system. If the metered size is larger than maxFsStatFiles, then ffiles and afiles will both be '0'.
	MaxFsStatFiles *string `json:"maxFsStatFiles,omitempty" tf:"max_fs_stat_files,omitempty"`

	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetID *string `json:"mountTargetId,omitempty" tf:"mount_target_id,omitempty"`

	// The current state of the export set.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// The date and time the export set was created, expressed in RFC 3339 timestamp format.  Example: 2016-08-25T21:10:29.600Z
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// The OCID of the virtual cloud network (VCN) the export set is in.
	VcnID *string `json:"vcnId,omitempty" tf:"vcn_id,omitempty"`
}

type StorageExportSetParameters struct {

	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: My export set
	// +kubebuilder:validation:Optional
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Controls the maximum tbytes, fbytes, and abytes, values reported by NFS FSSTAT calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The tbytes value reported by FSSTAT will be maxFsStatBytes. The value of fbytes and abytes will be maxFsStatBytes minus the metered size of the file system. If the metered size is larger than maxFsStatBytes, then fbytes and abytes will both be '0'.
	// +kubebuilder:validation:Optional
	MaxFsStatBytes *string `json:"maxFsStatBytes,omitempty" tf:"max_fs_stat_bytes,omitempty"`

	// (Updatable) Controls the maximum tfiles, ffiles, and afiles values reported by NFS FSSTAT calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The tfiles value reported by FSSTAT will be maxFsStatFiles. The value of ffiles and afiles will be maxFsStatFiles minus the metered size of the file system. If the metered size is larger than maxFsStatFiles, then ffiles and afiles will both be '0'.
	// +kubebuilder:validation:Optional
	MaxFsStatFiles *string `json:"maxFsStatFiles,omitempty" tf:"max_fs_stat_files,omitempty"`

	// (Updatable) The OCID of the mount target that the export set is associated with
	// +kubebuilder:validation:Optional
	MountTargetID *string `json:"mountTargetId,omitempty" tf:"mount_target_id,omitempty"`
}

// StorageExportSetSpec defines the desired state of StorageExportSet
type StorageExportSetSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     StorageExportSetParameters `json:"forProvider"`
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
	InitProvider StorageExportSetInitParameters `json:"initProvider,omitempty"`
}

// StorageExportSetStatus defines the observed state of StorageExportSet.
type StorageExportSetStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        StorageExportSetObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// StorageExportSet is the Schema for the StorageExportSets API. Provides the Export Set resource in Oracle Cloud Infrastructure File Storage service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type StorageExportSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.mountTargetId) || (has(self.initProvider) && has(self.initProvider.mountTargetId))",message="spec.forProvider.mountTargetId is a required parameter"
	Spec   StorageExportSetSpec   `json:"spec"`
	Status StorageExportSetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StorageExportSetList contains a list of StorageExportSets
type StorageExportSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StorageExportSet `json:"items"`
}

// Repository type metadata.
var (
	StorageExportSet_Kind             = "StorageExportSet"
	StorageExportSet_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: StorageExportSet_Kind}.String()
	StorageExportSet_KindAPIVersion   = StorageExportSet_Kind + "." + CRDGroupVersion.String()
	StorageExportSet_GroupVersionKind = CRDGroupVersion.WithKind(StorageExportSet_Kind)
)

func init() {
	SchemeBuilder.Register(&StorageExportSet{}, &StorageExportSetList{})
}
