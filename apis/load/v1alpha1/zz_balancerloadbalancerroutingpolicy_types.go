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

type ActionsInitParameters struct {

	// (Updatable) Name of the backend set the listener will forward the traffic to.  Example: backendSetForImages
	BackendSetName *string `json:"backendSetName,omitempty" tf:"backend_set_name,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

type ActionsObservation struct {

	// (Updatable) Name of the backend set the listener will forward the traffic to.  Example: backendSetForImages
	BackendSetName *string `json:"backendSetName,omitempty" tf:"backend_set_name,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

type ActionsParameters struct {

	// (Updatable) Name of the backend set the listener will forward the traffic to.  Example: backendSetForImages
	// +kubebuilder:validation:Optional
	BackendSetName *string `json:"backendSetName" tf:"backend_set_name,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	// +kubebuilder:validation:Optional
	Name *string `json:"name" tf:"name,omitempty"`
}

type BalancerLoadBalancerRoutingPolicyInitParameters struct {

	// (Updatable) The version of the language in which condition of rules are composed.
	ConditionLanguageVersion *string `json:"conditionLanguageVersion,omitempty" tf:"condition_language_version,omitempty"`

	// The OCID of the load balancer to add the routing policy rule list to.
	LoadBalancerID *string `json:"loadBalancerId,omitempty" tf:"load_balancer_id,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Updatable) The list of routing rules.
	Rules []RulesInitParameters `json:"rules,omitempty" tf:"rules,omitempty"`
}

type BalancerLoadBalancerRoutingPolicyObservation struct {

	// (Updatable) The version of the language in which condition of rules are composed.
	ConditionLanguageVersion *string `json:"conditionLanguageVersion,omitempty" tf:"condition_language_version,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The OCID of the load balancer to add the routing policy rule list to.
	LoadBalancerID *string `json:"loadBalancerId,omitempty" tf:"load_balancer_id,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Updatable) The list of routing rules.
	Rules []RulesObservation `json:"rules,omitempty" tf:"rules,omitempty"`

	State *string `json:"state,omitempty" tf:"state,omitempty"`
}

type BalancerLoadBalancerRoutingPolicyParameters struct {

	// (Updatable) The version of the language in which condition of rules are composed.
	// +kubebuilder:validation:Optional
	ConditionLanguageVersion *string `json:"conditionLanguageVersion,omitempty" tf:"condition_language_version,omitempty"`

	// The OCID of the load balancer to add the routing policy rule list to.
	// +kubebuilder:validation:Optional
	LoadBalancerID *string `json:"loadBalancerId,omitempty" tf:"load_balancer_id,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Updatable) The list of routing rules.
	// +kubebuilder:validation:Optional
	Rules []RulesParameters `json:"rules,omitempty" tf:"rules,omitempty"`
}

type RulesInitParameters struct {

	// (Updatable) A list of actions to be applied when conditions of the routing rule are met.
	Actions []ActionsInitParameters `json:"actions,omitempty" tf:"actions,omitempty"`

	// (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
	Condition *string `json:"condition,omitempty" tf:"condition,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

type RulesObservation struct {

	// (Updatable) A list of actions to be applied when conditions of the routing rule are met.
	Actions []ActionsObservation `json:"actions,omitempty" tf:"actions,omitempty"`

	// (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
	Condition *string `json:"condition,omitempty" tf:"condition,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

type RulesParameters struct {

	// (Updatable) A list of actions to be applied when conditions of the routing rule are met.
	// +kubebuilder:validation:Optional
	Actions []ActionsParameters `json:"actions" tf:"actions,omitempty"`

	// (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
	// +kubebuilder:validation:Optional
	Condition *string `json:"condition" tf:"condition,omitempty"`

	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: example_routing_rules
	// +kubebuilder:validation:Optional
	Name *string `json:"name" tf:"name,omitempty"`
}

// BalancerLoadBalancerRoutingPolicySpec defines the desired state of BalancerLoadBalancerRoutingPolicy
type BalancerLoadBalancerRoutingPolicySpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BalancerLoadBalancerRoutingPolicyParameters `json:"forProvider"`
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
	InitProvider BalancerLoadBalancerRoutingPolicyInitParameters `json:"initProvider,omitempty"`
}

// BalancerLoadBalancerRoutingPolicyStatus defines the observed state of BalancerLoadBalancerRoutingPolicy.
type BalancerLoadBalancerRoutingPolicyStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BalancerLoadBalancerRoutingPolicyObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// BalancerLoadBalancerRoutingPolicy is the Schema for the BalancerLoadBalancerRoutingPolicys API. Provides the Load Balancer Routing Policy resource in Oracle Cloud Infrastructure Load Balancer service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type BalancerLoadBalancerRoutingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.conditionLanguageVersion) || (has(self.initProvider) && has(self.initProvider.conditionLanguageVersion))",message="spec.forProvider.conditionLanguageVersion is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.loadBalancerId) || (has(self.initProvider) && has(self.initProvider.loadBalancerId))",message="spec.forProvider.loadBalancerId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.rules) || (has(self.initProvider) && has(self.initProvider.rules))",message="spec.forProvider.rules is a required parameter"
	Spec   BalancerLoadBalancerRoutingPolicySpec   `json:"spec"`
	Status BalancerLoadBalancerRoutingPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BalancerLoadBalancerRoutingPolicyList contains a list of BalancerLoadBalancerRoutingPolicys
type BalancerLoadBalancerRoutingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BalancerLoadBalancerRoutingPolicy `json:"items"`
}

// Repository type metadata.
var (
	BalancerLoadBalancerRoutingPolicy_Kind             = "BalancerLoadBalancerRoutingPolicy"
	BalancerLoadBalancerRoutingPolicy_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: BalancerLoadBalancerRoutingPolicy_Kind}.String()
	BalancerLoadBalancerRoutingPolicy_KindAPIVersion   = BalancerLoadBalancerRoutingPolicy_Kind + "." + CRDGroupVersion.String()
	BalancerLoadBalancerRoutingPolicy_GroupVersionKind = CRDGroupVersion.WithKind(BalancerLoadBalancerRoutingPolicy_Kind)
)

func init() {
	SchemeBuilder.Register(&BalancerLoadBalancerRoutingPolicy{}, &BalancerLoadBalancerRoutingPolicyList{})
}
