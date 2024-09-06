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

type ContainerRepositoryInitParameters struct {

	// (Updatable) The OCID of the compartment in which to create the resource.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// The container repository name.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
	IsImmutable *bool `json:"isImmutable,omitempty" tf:"is_immutable,omitempty"`

	// (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
	IsPublic *bool `json:"isPublic,omitempty" tf:"is_public,omitempty"`

	// (Updatable) Container repository readme.
	Readme []ReadmeInitParameters `json:"readme,omitempty" tf:"readme,omitempty"`
}

type ContainerRepositoryObservation struct {

	// Total storage size in GBs that will be charged.
	BillableSizeInGbs *string `json:"billableSizeInGbs,omitempty" tf:"billable_size_in_gbs,omitempty"`

	// (Updatable) The OCID of the compartment in which to create the resource.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// The id of the user or principal that created the resource.
	CreatedBy *string `json:"createdBy,omitempty" tf:"created_by,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// The container repository name.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The OCID of the container repository.  Example: ocid1.containerrepo.oc1..exampleuniqueID
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Total number of images.
	ImageCount *float64 `json:"imageCount,omitempty" tf:"image_count,omitempty"`

	// (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
	IsImmutable *bool `json:"isImmutable,omitempty" tf:"is_immutable,omitempty"`

	// (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
	IsPublic *bool `json:"isPublic,omitempty" tf:"is_public,omitempty"`

	// Total number of layers.
	LayerCount *float64 `json:"layerCount,omitempty" tf:"layer_count,omitempty"`

	// Total storage in bytes consumed by layers.
	LayersSizeInBytes *string `json:"layersSizeInBytes,omitempty" tf:"layers_size_in_bytes,omitempty"`

	// The tenancy namespace used in the container repository path.
	Namespace *string `json:"namespace,omitempty" tf:"namespace,omitempty"`

	// (Updatable) Container repository readme.
	Readme []ReadmeObservation `json:"readme,omitempty" tf:"readme,omitempty"`

	// The current state of the container repository.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// The system tags for this resource. Each key is predefined and scoped to a namespace. Example: {"orcl-cloud.free-tier-retained": "true"}
	// +mapType=granular
	SystemTags map[string]*string `json:"systemTags,omitempty" tf:"system_tags,omitempty"`

	// An RFC 3339 timestamp indicating when the repository was created.
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// An RFC 3339 timestamp indicating when an image was last pushed to the repository.
	TimeLastPushed *string `json:"timeLastPushed,omitempty" tf:"time_last_pushed,omitempty"`
}

type ContainerRepositoryParameters struct {

	// (Updatable) The OCID of the compartment in which to create the resource.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.  Example: {"Operations.CostCenter": "42"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// The container repository name.
	// +kubebuilder:validation:Optional
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags.  Example: {"Department": "Finance"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
	// +kubebuilder:validation:Optional
	IsImmutable *bool `json:"isImmutable,omitempty" tf:"is_immutable,omitempty"`

	// (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
	// +kubebuilder:validation:Optional
	IsPublic *bool `json:"isPublic,omitempty" tf:"is_public,omitempty"`

	// (Updatable) Container repository readme.
	// +kubebuilder:validation:Optional
	Readme []ReadmeParameters `json:"readme,omitempty" tf:"readme,omitempty"`
}

type ReadmeInitParameters struct {

	// (Updatable) Readme content. Avoid entering confidential information.
	Content *string `json:"content,omitempty" tf:"content,omitempty"`

	// (Updatable) Readme format. Supported formats are text/plain and text/markdown.
	Format *string `json:"format,omitempty" tf:"format,omitempty"`
}

type ReadmeObservation struct {

	// (Updatable) Readme content. Avoid entering confidential information.
	Content *string `json:"content,omitempty" tf:"content,omitempty"`

	// (Updatable) Readme format. Supported formats are text/plain and text/markdown.
	Format *string `json:"format,omitempty" tf:"format,omitempty"`
}

type ReadmeParameters struct {

	// (Updatable) Readme content. Avoid entering confidential information.
	// +kubebuilder:validation:Optional
	Content *string `json:"content" tf:"content,omitempty"`

	// (Updatable) Readme format. Supported formats are text/plain and text/markdown.
	// +kubebuilder:validation:Optional
	Format *string `json:"format" tf:"format,omitempty"`
}

// ContainerRepositorySpec defines the desired state of ContainerRepository
type ContainerRepositorySpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ContainerRepositoryParameters `json:"forProvider"`
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
	InitProvider ContainerRepositoryInitParameters `json:"initProvider,omitempty"`
}

// ContainerRepositoryStatus defines the observed state of ContainerRepository.
type ContainerRepositoryStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ContainerRepositoryObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// ContainerRepository is the Schema for the ContainerRepositorys API. Provides the Container Repository resource in Oracle Cloud Infrastructure Artifacts service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type ContainerRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.compartmentId) || (has(self.initProvider) && has(self.initProvider.compartmentId))",message="spec.forProvider.compartmentId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.displayName) || (has(self.initProvider) && has(self.initProvider.displayName))",message="spec.forProvider.displayName is a required parameter"
	Spec   ContainerRepositorySpec   `json:"spec"`
	Status ContainerRepositoryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ContainerRepositoryList contains a list of ContainerRepositorys
type ContainerRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ContainerRepository `json:"items"`
}

// Repository type metadata.
var (
	ContainerRepository_Kind             = "ContainerRepository"
	ContainerRepository_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ContainerRepository_Kind}.String()
	ContainerRepository_KindAPIVersion   = ContainerRepository_Kind + "." + CRDGroupVersion.String()
	ContainerRepository_GroupVersionKind = CRDGroupVersion.WithKind(ContainerRepository_Kind)
)

func init() {
	SchemeBuilder.Register(&ContainerRepository{}, &ContainerRepositoryList{})
}
