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

type KeyVersionExternalKeyReferenceDetailsInitParameters struct {
}

type KeyVersionExternalKeyReferenceDetailsObservation struct {

	// ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM.
	ExternalKeyID *string `json:"externalKeyId,omitempty" tf:"external_key_id,omitempty"`

	// Key version ID associated with the external key.
	ExternalKeyVersionID *string `json:"externalKeyVersionId,omitempty" tf:"external_key_version_id,omitempty"`
}

type KeyVersionExternalKeyReferenceDetailsParameters struct {
}

type KeyVersionInitParameters struct {

	// Key version ID associated with the external key.
	ExternalKeyVersionID *string `json:"externalKeyVersionId,omitempty" tf:"external_key_version_id,omitempty"`

	// The OCID of the key.
	KeyID *string `json:"keyId,omitempty" tf:"key_id,omitempty"`

	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint *string `json:"managementEndpoint,omitempty" tf:"management_endpoint,omitempty"`

	// (Updatable) An optional property for the deletion time of the key version, expressed in RFC 3339 timestamp format. Example: 2019-04-03T21:10:29.600Z
	TimeOfDeletion *string `json:"timeOfDeletion,omitempty" tf:"time_of_deletion,omitempty"`
}

type KeyVersionObservation struct {

	// The OCID of the compartment that contains this key version.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// Key reference data to be returned to the customer as a response.
	ExternalKeyReferenceDetails []KeyVersionExternalKeyReferenceDetailsObservation `json:"externalKeyReferenceDetails,omitempty" tf:"external_key_reference_details,omitempty"`

	// Key version ID associated with the external key.
	ExternalKeyVersionID *string `json:"externalKeyVersionId,omitempty" tf:"external_key_version_id,omitempty"`

	// The OCID of the key version.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// An optional property indicating whether this keyversion is generated from auto rotatation.
	IsAutoRotated *bool `json:"isAutoRotated,omitempty" tf:"is_auto_rotated,omitempty"`

	// A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
	IsPrimary *bool `json:"isPrimary,omitempty" tf:"is_primary,omitempty"`

	// The OCID of the key.
	KeyID *string `json:"keyId,omitempty" tf:"key_id,omitempty"`

	// The OCID of the key version.
	KeyVersionID *string `json:"keyVersionId,omitempty" tf:"key_version_id,omitempty"`

	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint *string `json:"managementEndpoint,omitempty" tf:"management_endpoint,omitempty"`

	// The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
	PublicKey *string `json:"publicKey,omitempty" tf:"public_key,omitempty"`

	// KeyVersion replica details
	ReplicaDetails []KeyVersionReplicaDetailsObservation `json:"replicaDetails,omitempty" tf:"replica_details,omitempty"`

	// The OCID of the key.
	RestoredFromKeyID *string `json:"restoredFromKeyId,omitempty" tf:"restored_from_key_id,omitempty"`

	// The OCID of the key version from which this key version was restored.
	RestoredFromKeyVersionID *string `json:"restoredFromKeyVersionId,omitempty" tf:"restored_from_key_version_id,omitempty"`

	// The key version's current lifecycle state.  Example: ENABLED
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// The date and time this key version was created, expressed in RFC 3339 timestamp format.  Example: "2018-04-03T21:10:29.600Z"
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// (Updatable) An optional property for the deletion time of the key version, expressed in RFC 3339 timestamp format. Example: 2019-04-03T21:10:29.600Z
	TimeOfDeletion *string `json:"timeOfDeletion,omitempty" tf:"time_of_deletion,omitempty"`

	// The OCID of the vault that contains this key version.
	VaultID *string `json:"vaultId,omitempty" tf:"vault_id,omitempty"`
}

type KeyVersionParameters struct {

	// Key version ID associated with the external key.
	// +kubebuilder:validation:Optional
	ExternalKeyVersionID *string `json:"externalKeyVersionId,omitempty" tf:"external_key_version_id,omitempty"`

	// The OCID of the key.
	// +kubebuilder:validation:Optional
	KeyID *string `json:"keyId,omitempty" tf:"key_id,omitempty"`

	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	// +kubebuilder:validation:Optional
	ManagementEndpoint *string `json:"managementEndpoint,omitempty" tf:"management_endpoint,omitempty"`

	// (Updatable) An optional property for the deletion time of the key version, expressed in RFC 3339 timestamp format. Example: 2019-04-03T21:10:29.600Z
	// +kubebuilder:validation:Optional
	TimeOfDeletion *string `json:"timeOfDeletion,omitempty" tf:"time_of_deletion,omitempty"`
}

type KeyVersionReplicaDetailsInitParameters struct {
}

type KeyVersionReplicaDetailsObservation struct {

	// ReplicationId associated with a key version operation
	ReplicationID *string `json:"replicationId,omitempty" tf:"replication_id,omitempty"`
}

type KeyVersionReplicaDetailsParameters struct {
}

// KeyVersionSpec defines the desired state of KeyVersion
type KeyVersionSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     KeyVersionParameters `json:"forProvider"`
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
	InitProvider KeyVersionInitParameters `json:"initProvider,omitempty"`
}

// KeyVersionStatus defines the observed state of KeyVersion.
type KeyVersionStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        KeyVersionObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// KeyVersion is the Schema for the KeyVersions API. Provides the Key Version resource in Oracle Cloud Infrastructure Kms service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type KeyVersion struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.keyId) || (has(self.initProvider) && has(self.initProvider.keyId))",message="spec.forProvider.keyId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.managementEndpoint) || (has(self.initProvider) && has(self.initProvider.managementEndpoint))",message="spec.forProvider.managementEndpoint is a required parameter"
	Spec   KeyVersionSpec   `json:"spec"`
	Status KeyVersionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeyVersionList contains a list of KeyVersions
type KeyVersionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeyVersion `json:"items"`
}

// Repository type metadata.
var (
	KeyVersion_Kind             = "KeyVersion"
	KeyVersion_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: KeyVersion_Kind}.String()
	KeyVersion_KindAPIVersion   = KeyVersion_Kind + "." + CRDGroupVersion.String()
	KeyVersion_GroupVersionKind = CRDGroupVersion.WithKind(KeyVersion_Kind)
)

func init() {
	SchemeBuilder.Register(&KeyVersion{}, &KeyVersionList{})
}
