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

type AutoKeyRotationDetailsInitParameters struct {

	// (Updatable) The last execution status message of auto key rotation.
	LastRotationMessage *string `json:"lastRotationMessage,omitempty" tf:"last_rotation_message,omitempty"`

	// (Updatable) The status of last execution of auto key rotation.
	LastRotationStatus *string `json:"lastRotationStatus,omitempty" tf:"last_rotation_status,omitempty"`

	// (Updatable) The interval of auto key rotation. For auto key rotation the interval should between 60 day and 365 days (1 year). Note: User must specify this parameter when creating a new schedule.
	RotationIntervalInDays *float64 `json:"rotationIntervalInDays,omitempty" tf:"rotation_interval_in_days,omitempty"`

	// (Updatable) A property indicating Last rotation Date. Example: 2023-04-04T00:00:00Z.
	TimeOfLastRotation *string `json:"timeOfLastRotation,omitempty" tf:"time_of_last_rotation,omitempty"`

	// (Updatable) A property indicating Next estimated scheduled Time, as per the interval, expressed as date YYYY-MM-DD String. Example: 2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z.
	TimeOfNextRotation *string `json:"timeOfNextRotation,omitempty" tf:"time_of_next_rotation,omitempty"`

	// (Updatable) A property indicating  scheduled start date expressed as date YYYY-MM-DD String. Example: `2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z . Note : Today’s date will be used if not specified by customer.
	TimeOfScheduleStart *string `json:"timeOfScheduleStart,omitempty" tf:"time_of_schedule_start,omitempty"`
}

type AutoKeyRotationDetailsObservation struct {

	// (Updatable) The last execution status message of auto key rotation.
	LastRotationMessage *string `json:"lastRotationMessage,omitempty" tf:"last_rotation_message,omitempty"`

	// (Updatable) The status of last execution of auto key rotation.
	LastRotationStatus *string `json:"lastRotationStatus,omitempty" tf:"last_rotation_status,omitempty"`

	// (Updatable) The interval of auto key rotation. For auto key rotation the interval should between 60 day and 365 days (1 year). Note: User must specify this parameter when creating a new schedule.
	RotationIntervalInDays *float64 `json:"rotationIntervalInDays,omitempty" tf:"rotation_interval_in_days,omitempty"`

	// (Updatable) A property indicating Last rotation Date. Example: 2023-04-04T00:00:00Z.
	TimeOfLastRotation *string `json:"timeOfLastRotation,omitempty" tf:"time_of_last_rotation,omitempty"`

	// (Updatable) A property indicating Next estimated scheduled Time, as per the interval, expressed as date YYYY-MM-DD String. Example: 2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z.
	TimeOfNextRotation *string `json:"timeOfNextRotation,omitempty" tf:"time_of_next_rotation,omitempty"`

	// (Updatable) A property indicating  scheduled start date expressed as date YYYY-MM-DD String. Example: `2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z . Note : Today’s date will be used if not specified by customer.
	TimeOfScheduleStart *string `json:"timeOfScheduleStart,omitempty" tf:"time_of_schedule_start,omitempty"`
}

type AutoKeyRotationDetailsParameters struct {

	// (Updatable) The last execution status message of auto key rotation.
	// +kubebuilder:validation:Optional
	LastRotationMessage *string `json:"lastRotationMessage,omitempty" tf:"last_rotation_message,omitempty"`

	// (Updatable) The status of last execution of auto key rotation.
	// +kubebuilder:validation:Optional
	LastRotationStatus *string `json:"lastRotationStatus,omitempty" tf:"last_rotation_status,omitempty"`

	// (Updatable) The interval of auto key rotation. For auto key rotation the interval should between 60 day and 365 days (1 year). Note: User must specify this parameter when creating a new schedule.
	// +kubebuilder:validation:Optional
	RotationIntervalInDays *float64 `json:"rotationIntervalInDays,omitempty" tf:"rotation_interval_in_days,omitempty"`

	// (Updatable) A property indicating Last rotation Date. Example: 2023-04-04T00:00:00Z.
	// +kubebuilder:validation:Optional
	TimeOfLastRotation *string `json:"timeOfLastRotation,omitempty" tf:"time_of_last_rotation,omitempty"`

	// (Updatable) A property indicating Next estimated scheduled Time, as per the interval, expressed as date YYYY-MM-DD String. Example: 2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z.
	// +kubebuilder:validation:Optional
	TimeOfNextRotation *string `json:"timeOfNextRotation,omitempty" tf:"time_of_next_rotation,omitempty"`

	// (Updatable) A property indicating  scheduled start date expressed as date YYYY-MM-DD String. Example: `2023-04-04T00:00:00Z. The time has no significance when scheduling an auto key rotation as this can be done anytime approximately the scheduled day, KMS ignores the time and replaces it with 00:00, for example 2023-04-04T15:14:13Z will be used as 2023-04-04T00:00:00Z . Note : Today’s date will be used if not specified by customer.
	// +kubebuilder:validation:Optional
	TimeOfScheduleStart *string `json:"timeOfScheduleStart,omitempty" tf:"time_of_schedule_start,omitempty"`
}

type ExternalKeyReferenceDetailsInitParameters struct {
}

type ExternalKeyReferenceDetailsObservation struct {

	// ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM
	ExternalKeyID *string `json:"externalKeyId,omitempty" tf:"external_key_id,omitempty"`

	// Key version ID associated with the external key.
	ExternalKeyVersionID *string `json:"externalKeyVersionId,omitempty" tf:"external_key_version_id,omitempty"`
}

type ExternalKeyReferenceDetailsParameters struct {
}

type ExternalKeyReferenceInitParameters struct {

	// ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM
	ExternalKeyID *string `json:"externalKeyId,omitempty" tf:"external_key_id,omitempty"`
}

type ExternalKeyReferenceObservation struct {

	// ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM
	ExternalKeyID *string `json:"externalKeyId,omitempty" tf:"external_key_id,omitempty"`
}

type ExternalKeyReferenceParameters struct {

	// ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM
	// +kubebuilder:validation:Optional
	ExternalKeyID *string `json:"externalKeyId" tf:"external_key_id,omitempty"`
}

type KeyInitParameters struct {

	// (Updatable) The details of auto rotation schedule for the Key being create updated or imported.
	AutoKeyRotationDetails []AutoKeyRotationDetailsInitParameters `json:"autoKeyRotationDetails,omitempty" tf:"auto_key_rotation_details,omitempty"`

	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Desired state of the key. Possible values : ENABLED or DISABLED
	DesiredState *string `json:"desiredState,omitempty" tf:"desired_state,omitempty"`

	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// A reference to the key on external key manager.
	ExternalKeyReference []ExternalKeyReferenceInitParameters `json:"externalKeyReference,omitempty" tf:"external_key_reference,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags. Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) A parameter specifying whether the auto key rotation is enabled or not.
	IsAutoRotationEnabled *bool `json:"isAutoRotationEnabled,omitempty" tf:"is_auto_rotation_enabled,omitempty"`

	// The cryptographic properties of a key.
	KeyShape []KeyShapeInitParameters `json:"keyShape,omitempty" tf:"key_shape,omitempty"`

	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint *string `json:"managementEndpoint,omitempty" tf:"management_endpoint,omitempty"`

	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of HSM means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of SOFTWARE means that the key persists on the server, protected by the vault's RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of SOFTWARE are performed on the server. By default, a key's protection mode is set to HSM. You can't change a key's protection mode after the key is created or imported. A protection mode of EXTERNAL mean that the key persists on the customer's external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of EXTERNAL are performed by external key manager.
	ProtectionMode *string `json:"protectionMode,omitempty" tf:"protection_mode,omitempty"`

	// (Updatable) Details where key was backed up.
	RestoreFromFile []RestoreFromFileInitParameters `json:"restoreFromFile,omitempty" tf:"restore_from_file,omitempty"`

	// (Updatable) Details where key was backed up
	RestoreFromObjectStore []RestoreFromObjectStoreInitParameters `json:"restoreFromObjectStore,omitempty" tf:"restore_from_object_store,omitempty"`

	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger *bool `json:"restoreTrigger,omitempty" tf:"restore_trigger,omitempty"`

	// (Updatable) An optional property for the deletion time of the key, expressed in RFC 3339 timestamp format. Example: 2019-04-03T21:10:29.600Z
	TimeOfDeletion *string `json:"timeOfDeletion,omitempty" tf:"time_of_deletion,omitempty"`
}

type KeyObservation struct {

	// (Updatable) The details of auto rotation schedule for the Key being create updated or imported.
	AutoKeyRotationDetails []AutoKeyRotationDetailsObservation `json:"autoKeyRotationDetails,omitempty" tf:"auto_key_rotation_details,omitempty"`

	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The currentKeyVersion property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
	CurrentKeyVersion *string `json:"currentKeyVersion,omitempty" tf:"current_key_version,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: {"Operations.CostCenter": "42"}
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Desired state of the key. Possible values : ENABLED or DISABLED
	DesiredState *string `json:"desiredState,omitempty" tf:"desired_state,omitempty"`

	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// A reference to the key on external key manager.
	ExternalKeyReference []ExternalKeyReferenceObservation `json:"externalKeyReference,omitempty" tf:"external_key_reference,omitempty"`

	// Key reference data to be returned to the customer as a response.
	ExternalKeyReferenceDetails []ExternalKeyReferenceDetailsObservation `json:"externalKeyReferenceDetails,omitempty" tf:"external_key_reference_details,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags. Example: {"Department": "Finance"}
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// The OCID of the key.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Updatable) A parameter specifying whether the auto key rotation is enabled or not.
	IsAutoRotationEnabled *bool `json:"isAutoRotationEnabled,omitempty" tf:"is_auto_rotation_enabled,omitempty"`

	// A Boolean value that indicates whether the Key belongs to primary Vault or replica vault.
	IsPrimary *bool `json:"isPrimary,omitempty" tf:"is_primary,omitempty"`

	// The cryptographic properties of a key.
	KeyShape []KeyShapeObservation `json:"keyShape,omitempty" tf:"key_shape,omitempty"`

	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	ManagementEndpoint *string `json:"managementEndpoint,omitempty" tf:"management_endpoint,omitempty"`

	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of HSM means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of SOFTWARE means that the key persists on the server, protected by the vault's RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of SOFTWARE are performed on the server. By default, a key's protection mode is set to HSM. You can't change a key's protection mode after the key is created or imported. A protection mode of EXTERNAL mean that the key persists on the customer's external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of EXTERNAL are performed by external key manager.
	ProtectionMode *string `json:"protectionMode,omitempty" tf:"protection_mode,omitempty"`

	// Key replica details
	ReplicaDetails []ReplicaDetailsObservation `json:"replicaDetails,omitempty" tf:"replica_details,omitempty"`

	// (Updatable) Details where key was backed up.
	RestoreFromFile []RestoreFromFileObservation `json:"restoreFromFile,omitempty" tf:"restore_from_file,omitempty"`

	// (Updatable) Details where key was backed up
	RestoreFromObjectStore []RestoreFromObjectStoreObservation `json:"restoreFromObjectStore,omitempty" tf:"restore_from_object_store,omitempty"`

	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	RestoreTrigger *bool `json:"restoreTrigger,omitempty" tf:"restore_trigger,omitempty"`

	// The OCID of the key from which this key was restored.
	RestoredFromKeyID *string `json:"restoredFromKeyId,omitempty" tf:"restored_from_key_id,omitempty"`

	// The key's current lifecycle state.  Example: ENABLED
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// The date and time the key was created, expressed in RFC 3339 timestamp format.  Example: 2018-04-03T21:10:29.600Z
	TimeCreated *string `json:"timeCreated,omitempty" tf:"time_created,omitempty"`

	// (Updatable) An optional property for the deletion time of the key, expressed in RFC 3339 timestamp format. Example: 2019-04-03T21:10:29.600Z
	TimeOfDeletion *string `json:"timeOfDeletion,omitempty" tf:"time_of_deletion,omitempty"`

	// The OCID of the vault that contains this key.
	VaultID *string `json:"vaultId,omitempty" tf:"vault_id,omitempty"`
}

type KeyParameters struct {

	// (Updatable) The details of auto rotation schedule for the Key being create updated or imported.
	// +kubebuilder:validation:Optional
	AutoKeyRotationDetails []AutoKeyRotationDetailsParameters `json:"autoKeyRotationDetails,omitempty" tf:"auto_key_rotation_details,omitempty"`

	// (Updatable) The OCID of the compartment where you want to create the master encryption key.
	// +kubebuilder:validation:Optional
	CompartmentID *string `json:"compartmentId,omitempty" tf:"compartment_id,omitempty"`

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: {"Operations.CostCenter": "42"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	DefinedTags map[string]*string `json:"definedTags,omitempty" tf:"defined_tags,omitempty"`

	// (Updatable) Desired state of the key. Possible values : ENABLED or DISABLED
	// +kubebuilder:validation:Optional
	DesiredState *string `json:"desiredState,omitempty" tf:"desired_state,omitempty"`

	// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	// +kubebuilder:validation:Optional
	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	// A reference to the key on external key manager.
	// +kubebuilder:validation:Optional
	ExternalKeyReference []ExternalKeyReferenceParameters `json:"externalKeyReference,omitempty" tf:"external_key_reference,omitempty"`

	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see Resource Tags. Example: {"Department": "Finance"}
	// +kubebuilder:validation:Optional
	// +mapType=granular
	FreeformTags map[string]*string `json:"freeformTags,omitempty" tf:"freeform_tags,omitempty"`

	// (Updatable) A parameter specifying whether the auto key rotation is enabled or not.
	// +kubebuilder:validation:Optional
	IsAutoRotationEnabled *bool `json:"isAutoRotationEnabled,omitempty" tf:"is_auto_rotation_enabled,omitempty"`

	// The cryptographic properties of a key.
	// +kubebuilder:validation:Optional
	KeyShape []KeyShapeParameters `json:"keyShape,omitempty" tf:"key_shape,omitempty"`

	// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
	// +kubebuilder:validation:Optional
	ManagementEndpoint *string `json:"managementEndpoint,omitempty" tf:"management_endpoint,omitempty"`

	// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of HSM means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of SOFTWARE means that the key persists on the server, protected by the vault's RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of SOFTWARE are performed on the server. By default, a key's protection mode is set to HSM. You can't change a key's protection mode after the key is created or imported. A protection mode of EXTERNAL mean that the key persists on the customer's external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of EXTERNAL are performed by external key manager.
	// +kubebuilder:validation:Optional
	ProtectionMode *string `json:"protectionMode,omitempty" tf:"protection_mode,omitempty"`

	// (Updatable) Details where key was backed up.
	// +kubebuilder:validation:Optional
	RestoreFromFile []RestoreFromFileParameters `json:"restoreFromFile,omitempty" tf:"restore_from_file,omitempty"`

	// (Updatable) Details where key was backed up
	// +kubebuilder:validation:Optional
	RestoreFromObjectStore []RestoreFromObjectStoreParameters `json:"restoreFromObjectStore,omitempty" tf:"restore_from_object_store,omitempty"`

	// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
	// +kubebuilder:validation:Optional
	RestoreTrigger *bool `json:"restoreTrigger,omitempty" tf:"restore_trigger,omitempty"`

	// (Updatable) An optional property for the deletion time of the key, expressed in RFC 3339 timestamp format. Example: 2019-04-03T21:10:29.600Z
	// +kubebuilder:validation:Optional
	TimeOfDeletion *string `json:"timeOfDeletion,omitempty" tf:"time_of_deletion,omitempty"`
}

type KeyShapeInitParameters struct {

	// The algorithm used by a key's key versions to encrypt or decrypt. Only AES algorithm is supported for External keys.
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// Supported curve IDs for ECDSA keys.
	CurveID *string `json:"curveId,omitempty" tf:"curve_id,omitempty"`

	// The length of the key in bytes, expressed as an integer. Supported values include the following:
	Length *float64 `json:"length,omitempty" tf:"length,omitempty"`
}

type KeyShapeObservation struct {

	// The algorithm used by a key's key versions to encrypt or decrypt. Only AES algorithm is supported for External keys.
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// Supported curve IDs for ECDSA keys.
	CurveID *string `json:"curveId,omitempty" tf:"curve_id,omitempty"`

	// The length of the key in bytes, expressed as an integer. Supported values include the following:
	Length *float64 `json:"length,omitempty" tf:"length,omitempty"`
}

type KeyShapeParameters struct {

	// The algorithm used by a key's key versions to encrypt or decrypt. Only AES algorithm is supported for External keys.
	// +kubebuilder:validation:Optional
	Algorithm *string `json:"algorithm" tf:"algorithm,omitempty"`

	// Supported curve IDs for ECDSA keys.
	// +kubebuilder:validation:Optional
	CurveID *string `json:"curveId,omitempty" tf:"curve_id,omitempty"`

	// The length of the key in bytes, expressed as an integer. Supported values include the following:
	// +kubebuilder:validation:Optional
	Length *float64 `json:"length" tf:"length,omitempty"`
}

type ReplicaDetailsInitParameters struct {
}

type ReplicaDetailsObservation struct {

	// ReplicationId associated with a key operation
	ReplicationID *string `json:"replicationId,omitempty" tf:"replication_id,omitempty"`
}

type ReplicaDetailsParameters struct {
}

type RestoreFromFileInitParameters struct {

	// (Updatable) content length of key's backup binary file
	ContentLength *string `json:"contentLength,omitempty" tf:"content_length,omitempty"`

	// (Updatable) content md5 hashed value of key's backup file
	ContentMd5 *string `json:"contentMd5,omitempty" tf:"content_md5,omitempty"`

	// Key backup file content.
	RestoreKeyFromFileDetails *string `json:"restoreKeyFromFileDetails,omitempty" tf:"restore_key_from_file_details,omitempty"`
}

type RestoreFromFileObservation struct {

	// (Updatable) content length of key's backup binary file
	ContentLength *string `json:"contentLength,omitempty" tf:"content_length,omitempty"`

	// (Updatable) content md5 hashed value of key's backup file
	ContentMd5 *string `json:"contentMd5,omitempty" tf:"content_md5,omitempty"`

	// Key backup file content.
	RestoreKeyFromFileDetails *string `json:"restoreKeyFromFileDetails,omitempty" tf:"restore_key_from_file_details,omitempty"`
}

type RestoreFromFileParameters struct {

	// (Updatable) content length of key's backup binary file
	// +kubebuilder:validation:Optional
	ContentLength *string `json:"contentLength" tf:"content_length,omitempty"`

	// (Updatable) content md5 hashed value of key's backup file
	// +kubebuilder:validation:Optional
	ContentMd5 *string `json:"contentMd5,omitempty" tf:"content_md5,omitempty"`

	// Key backup file content.
	// +kubebuilder:validation:Optional
	RestoreKeyFromFileDetails *string `json:"restoreKeyFromFileDetails" tf:"restore_key_from_file_details,omitempty"`
}

type RestoreFromObjectStoreInitParameters struct {

	// (Updatable) Name of the bucket where key was backed up
	Bucket *string `json:"bucket,omitempty" tf:"bucket,omitempty"`

	// (Updatable) Type of backup to restore from. Values of "BUCKET", "PRE_AUTHENTICATED_REQUEST_URI" are supported
	Destination *string `json:"destination,omitempty" tf:"destination,omitempty"`

	// (Updatable) Namespace of the bucket where key was backed up
	Namespace *string `json:"namespace,omitempty" tf:"namespace,omitempty"`

	// (Updatable) Object containing the backup
	Object *string `json:"object,omitempty" tf:"object,omitempty"`

	// (Updatable) Pre-authenticated-request-uri of the backup
	URI *string `json:"uri,omitempty" tf:"uri,omitempty"`
}

type RestoreFromObjectStoreObservation struct {

	// (Updatable) Name of the bucket where key was backed up
	Bucket *string `json:"bucket,omitempty" tf:"bucket,omitempty"`

	// (Updatable) Type of backup to restore from. Values of "BUCKET", "PRE_AUTHENTICATED_REQUEST_URI" are supported
	Destination *string `json:"destination,omitempty" tf:"destination,omitempty"`

	// (Updatable) Namespace of the bucket where key was backed up
	Namespace *string `json:"namespace,omitempty" tf:"namespace,omitempty"`

	// (Updatable) Object containing the backup
	Object *string `json:"object,omitempty" tf:"object,omitempty"`

	// (Updatable) Pre-authenticated-request-uri of the backup
	URI *string `json:"uri,omitempty" tf:"uri,omitempty"`
}

type RestoreFromObjectStoreParameters struct {

	// (Updatable) Name of the bucket where key was backed up
	// +kubebuilder:validation:Optional
	Bucket *string `json:"bucket,omitempty" tf:"bucket,omitempty"`

	// (Updatable) Type of backup to restore from. Values of "BUCKET", "PRE_AUTHENTICATED_REQUEST_URI" are supported
	// +kubebuilder:validation:Optional
	Destination *string `json:"destination" tf:"destination,omitempty"`

	// (Updatable) Namespace of the bucket where key was backed up
	// +kubebuilder:validation:Optional
	Namespace *string `json:"namespace,omitempty" tf:"namespace,omitempty"`

	// (Updatable) Object containing the backup
	// +kubebuilder:validation:Optional
	Object *string `json:"object,omitempty" tf:"object,omitempty"`

	// (Updatable) Pre-authenticated-request-uri of the backup
	// +kubebuilder:validation:Optional
	URI *string `json:"uri,omitempty" tf:"uri,omitempty"`
}

// KeySpec defines the desired state of Key
type KeySpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     KeyParameters `json:"forProvider"`
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
	InitProvider KeyInitParameters `json:"initProvider,omitempty"`
}

// KeyStatus defines the observed state of Key.
type KeyStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        KeyObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Key is the Schema for the Keys API. Provides the Key resource in Oracle Cloud Infrastructure Kms service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type Key struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.compartmentId) || (has(self.initProvider) && has(self.initProvider.compartmentId))",message="spec.forProvider.compartmentId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.displayName) || (has(self.initProvider) && has(self.initProvider.displayName))",message="spec.forProvider.displayName is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.keyShape) || (has(self.initProvider) && has(self.initProvider.keyShape))",message="spec.forProvider.keyShape is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.managementEndpoint) || (has(self.initProvider) && has(self.initProvider.managementEndpoint))",message="spec.forProvider.managementEndpoint is a required parameter"
	Spec   KeySpec   `json:"spec"`
	Status KeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeyList contains a list of Keys
type KeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Key `json:"items"`
}

// Repository type metadata.
var (
	Key_Kind             = "Key"
	Key_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Key_Kind}.String()
	Key_KindAPIVersion   = Key_Kind + "." + CRDGroupVersion.String()
	Key_GroupVersionKind = CRDGroupVersion.WithKind(Key_Kind)
)

func init() {
	SchemeBuilder.Register(&Key{}, &KeyList{})
}
