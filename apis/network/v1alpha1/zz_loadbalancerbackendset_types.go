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

type BackendsInitParameters struct {
}

type BackendsObservation struct {

	// (Updatable) The IP address of the backend server.  Example: 10.0.0.3
	IPAddress *string `json:"ipAddress,omitempty" tf:"ip_address,omitempty"`

	// (Updatable) Whether the network load balancer should treat this server as a backup unit. If true, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "isBackup" fail the health check policy.  Example: false
	IsBackup *bool `json:"isBackup,omitempty" tf:"is_backup,omitempty"`

	// (Updatable) Whether the network load balancer should drain this server. Servers marked "isDrain" receive no incoming traffic.  Example: false
	IsDrain *bool `json:"isDrain,omitempty" tf:"is_drain,omitempty"`

	// (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: false
	IsOffline *bool `json:"isOffline,omitempty" tf:"is_offline,omitempty"`

	// (Updatable) A read-only field showing the IP address/OCID and port that uniquely identify this backend server in the backend set.  Example: 10.0.0.3:8080, or ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:443 or 10.0.0.3:0
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Updatable) The communication port for the backend server.  Example: 8080
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The IP OCID/Instance OCID associated with the backend server. Example: ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>
	TargetID *string `json:"targetId,omitempty" tf:"target_id,omitempty"`

	// (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives three times the number of new connections as a server weighted '1'. For more information about load balancing policies, see How Network Load Balancing Policies Work.  Example: 3
	Weight *float64 `json:"weight,omitempty" tf:"weight,omitempty"`
}

type BackendsParameters struct {
}

type DNSInitParameters struct {

	// (Updatable) The absolute fully-qualified domain name to perform periodic DNS queries. If not provided, an extra dot will be added at the end of a domain name during the query.
	DomainName *string `json:"domainName,omitempty" tf:"domain_name,omitempty"`

	// (Updatable) The class the dns health check query to use; either IN or CH.  Example: IN
	QueryClass *string `json:"queryClass,omitempty" tf:"query_class,omitempty"`

	// (Updatable) The type the dns health check query to use; A, AAAA, TXT.  Example: A
	QueryType *string `json:"queryType,omitempty" tf:"query_type,omitempty"`

	// (Updatable) An array that represents accepetable RCODE values for DNS query response. Example: ["NOERROR", "NXDOMAIN"]
	Rcodes []*string `json:"rcodes,omitempty" tf:"rcodes,omitempty"`

	// (Updatable) DNS transport protocol; either UDP or TCP.  Example: UDP
	TransportProtocol *string `json:"transportProtocol,omitempty" tf:"transport_protocol,omitempty"`
}

type DNSObservation struct {

	// (Updatable) The absolute fully-qualified domain name to perform periodic DNS queries. If not provided, an extra dot will be added at the end of a domain name during the query.
	DomainName *string `json:"domainName,omitempty" tf:"domain_name,omitempty"`

	// (Updatable) The class the dns health check query to use; either IN or CH.  Example: IN
	QueryClass *string `json:"queryClass,omitempty" tf:"query_class,omitempty"`

	// (Updatable) The type the dns health check query to use; A, AAAA, TXT.  Example: A
	QueryType *string `json:"queryType,omitempty" tf:"query_type,omitempty"`

	// (Updatable) An array that represents accepetable RCODE values for DNS query response. Example: ["NOERROR", "NXDOMAIN"]
	Rcodes []*string `json:"rcodes,omitempty" tf:"rcodes,omitempty"`

	// (Updatable) DNS transport protocol; either UDP or TCP.  Example: UDP
	TransportProtocol *string `json:"transportProtocol,omitempty" tf:"transport_protocol,omitempty"`
}

type DNSParameters struct {

	// (Updatable) The absolute fully-qualified domain name to perform periodic DNS queries. If not provided, an extra dot will be added at the end of a domain name during the query.
	// +kubebuilder:validation:Optional
	DomainName *string `json:"domainName" tf:"domain_name,omitempty"`

	// (Updatable) The class the dns health check query to use; either IN or CH.  Example: IN
	// +kubebuilder:validation:Optional
	QueryClass *string `json:"queryClass,omitempty" tf:"query_class,omitempty"`

	// (Updatable) The type the dns health check query to use; A, AAAA, TXT.  Example: A
	// +kubebuilder:validation:Optional
	QueryType *string `json:"queryType,omitempty" tf:"query_type,omitempty"`

	// (Updatable) An array that represents accepetable RCODE values for DNS query response. Example: ["NOERROR", "NXDOMAIN"]
	// +kubebuilder:validation:Optional
	Rcodes []*string `json:"rcodes,omitempty" tf:"rcodes,omitempty"`

	// (Updatable) DNS transport protocol; either UDP or TCP.  Example: UDP
	// +kubebuilder:validation:Optional
	TransportProtocol *string `json:"transportProtocol,omitempty" tf:"transport_protocol,omitempty"`
}

type HealthCheckerInitParameters struct {

	// (Updatable) DNS healthcheck configurations.
	DNS []DNSInitParameters `json:"dns,omitempty" tf:"dns,omitempty"`

	// (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: 10000
	IntervalInMillis *float64 `json:"intervalInMillis,omitempty" tf:"interval_in_millis,omitempty"`

	// (Updatable) The communication port for the backend server.  Example: 8080
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The protocol the health check must use; either HTTP, HTTPS, UDP, TCP or DNS.  Example: HTTP
	Protocol *string `json:"protocol,omitempty" tf:"protocol,omitempty"`

	// (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
	RequestData *string `json:"requestData,omitempty" tf:"request_data,omitempty"`

	// (Updatable) A regular expression for parsing the response body from the backend server.  Example: ^((?!false).|\s)*$
	ResponseBodyRegex *string `json:"responseBodyRegex,omitempty" tf:"response_body_regex,omitempty"`

	// (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
	ResponseData *string `json:"responseData,omitempty" tf:"response_data,omitempty"`

	// (Updatable) The number of retries to attempt before a backend server is considered "unhealthy". This number also applies when recovering a server to the "healthy" state. The default value is 3.  Example: 3
	Retries *float64 `json:"retries,omitempty" tf:"retries,omitempty"`

	// (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as "200".  Example: 200
	ReturnCode *float64 `json:"returnCode,omitempty" tf:"return_code,omitempty"`

	// (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: 3000
	TimeoutInMillis *float64 `json:"timeoutInMillis,omitempty" tf:"timeout_in_millis,omitempty"`

	// (Updatable) The path against which to run the health check.  Example: /healthcheck
	URLPath *string `json:"urlPath,omitempty" tf:"url_path,omitempty"`
}

type HealthCheckerObservation struct {

	// (Updatable) DNS healthcheck configurations.
	DNS []DNSObservation `json:"dns,omitempty" tf:"dns,omitempty"`

	// (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: 10000
	IntervalInMillis *float64 `json:"intervalInMillis,omitempty" tf:"interval_in_millis,omitempty"`

	// (Updatable) The communication port for the backend server.  Example: 8080
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The protocol the health check must use; either HTTP, HTTPS, UDP, TCP or DNS.  Example: HTTP
	Protocol *string `json:"protocol,omitempty" tf:"protocol,omitempty"`

	// (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
	RequestData *string `json:"requestData,omitempty" tf:"request_data,omitempty"`

	// (Updatable) A regular expression for parsing the response body from the backend server.  Example: ^((?!false).|\s)*$
	ResponseBodyRegex *string `json:"responseBodyRegex,omitempty" tf:"response_body_regex,omitempty"`

	// (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
	ResponseData *string `json:"responseData,omitempty" tf:"response_data,omitempty"`

	// (Updatable) The number of retries to attempt before a backend server is considered "unhealthy". This number also applies when recovering a server to the "healthy" state. The default value is 3.  Example: 3
	Retries *float64 `json:"retries,omitempty" tf:"retries,omitempty"`

	// (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as "200".  Example: 200
	ReturnCode *float64 `json:"returnCode,omitempty" tf:"return_code,omitempty"`

	// (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: 3000
	TimeoutInMillis *float64 `json:"timeoutInMillis,omitempty" tf:"timeout_in_millis,omitempty"`

	// (Updatable) The path against which to run the health check.  Example: /healthcheck
	URLPath *string `json:"urlPath,omitempty" tf:"url_path,omitempty"`
}

type HealthCheckerParameters struct {

	// (Updatable) DNS healthcheck configurations.
	// +kubebuilder:validation:Optional
	DNS []DNSParameters `json:"dns,omitempty" tf:"dns,omitempty"`

	// (Updatable) The interval between health checks, in milliseconds. The default value is 10000 (10 seconds).  Example: 10000
	// +kubebuilder:validation:Optional
	IntervalInMillis *float64 `json:"intervalInMillis,omitempty" tf:"interval_in_millis,omitempty"`

	// (Updatable) The communication port for the backend server.  Example: 8080
	// +kubebuilder:validation:Optional
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`

	// (Updatable) The protocol the health check must use; either HTTP, HTTPS, UDP, TCP or DNS.  Example: HTTP
	// +kubebuilder:validation:Optional
	Protocol *string `json:"protocol" tf:"protocol,omitempty"`

	// (Updatable) Base64 encoded pattern to be sent as UDP or TCP health check probe.
	// +kubebuilder:validation:Optional
	RequestData *string `json:"requestData,omitempty" tf:"request_data,omitempty"`

	// (Updatable) A regular expression for parsing the response body from the backend server.  Example: ^((?!false).|\s)*$
	// +kubebuilder:validation:Optional
	ResponseBodyRegex *string `json:"responseBodyRegex,omitempty" tf:"response_body_regex,omitempty"`

	// (Updatable) Base64 encoded pattern to be validated as UDP or TCP health check probe response.
	// +kubebuilder:validation:Optional
	ResponseData *string `json:"responseData,omitempty" tf:"response_data,omitempty"`

	// (Updatable) The number of retries to attempt before a backend server is considered "unhealthy". This number also applies when recovering a server to the "healthy" state. The default value is 3.  Example: 3
	// +kubebuilder:validation:Optional
	Retries *float64 `json:"retries,omitempty" tf:"retries,omitempty"`

	// (Updatable) The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, then you can use common HTTP status codes such as "200".  Example: 200
	// +kubebuilder:validation:Optional
	ReturnCode *float64 `json:"returnCode,omitempty" tf:"return_code,omitempty"`

	// (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. The default value is 3000 (3 seconds).  Example: 3000
	// +kubebuilder:validation:Optional
	TimeoutInMillis *float64 `json:"timeoutInMillis,omitempty" tf:"timeout_in_millis,omitempty"`

	// (Updatable) The path against which to run the health check.  Example: /healthcheck
	// +kubebuilder:validation:Optional
	URLPath *string `json:"urlPath,omitempty" tf:"url_path,omitempty"`
}

type LoadBalancerBackendSetInitParameters struct {

	// (Updatable) The health check policy configuration. For more information, see Editing Health Check Policies.
	HealthChecker []HealthCheckerInitParameters `json:"healthChecker,omitempty" tf:"health_checker,omitempty"`

	// (Updatable) IP version associated with the backend set.
	IPVersion *string `json:"ipVersion,omitempty" tf:"ip_version,omitempty"`

	// (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
	IsFailOpen *bool `json:"isFailOpen,omitempty" tf:"is_fail_open,omitempty"`

	// (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
	IsInstantFailoverEnabled *bool `json:"isInstantFailoverEnabled,omitempty" tf:"is_instant_failover_enabled,omitempty"`

	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource *bool `json:"isPreserveSource,omitempty" tf:"is_preserve_source,omitempty"`

	// (Updatable) A read-only field showing the IP address/OCID and port that uniquely identify this backend server in the backend set.  Example: 10.0.0.3:8080, or ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:443 or 10.0.0.3:0
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The OCID of the network load balancer to update.
	NetworkLoadBalancerID *string `json:"networkLoadBalancerId,omitempty" tf:"network_load_balancer_id,omitempty"`

	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE“
	Policy *string `json:"policy,omitempty" tf:"policy,omitempty"`
}

type LoadBalancerBackendSetObservation struct {

	// (Updatable) An array of backends to be associated with the backend set.
	Backends []BackendsObservation `json:"backends,omitempty" tf:"backends,omitempty"`

	// (Updatable) The health check policy configuration. For more information, see Editing Health Check Policies.
	HealthChecker []HealthCheckerObservation `json:"healthChecker,omitempty" tf:"health_checker,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Updatable) IP version associated with the backend set.
	IPVersion *string `json:"ipVersion,omitempty" tf:"ip_version,omitempty"`

	// (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
	IsFailOpen *bool `json:"isFailOpen,omitempty" tf:"is_fail_open,omitempty"`

	// (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
	IsInstantFailoverEnabled *bool `json:"isInstantFailoverEnabled,omitempty" tf:"is_instant_failover_enabled,omitempty"`

	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource *bool `json:"isPreserveSource,omitempty" tf:"is_preserve_source,omitempty"`

	// (Updatable) A read-only field showing the IP address/OCID and port that uniquely identify this backend server in the backend set.  Example: 10.0.0.3:8080, or ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:443 or 10.0.0.3:0
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The OCID of the network load balancer to update.
	NetworkLoadBalancerID *string `json:"networkLoadBalancerId,omitempty" tf:"network_load_balancer_id,omitempty"`

	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE“
	Policy *string `json:"policy,omitempty" tf:"policy,omitempty"`
}

type LoadBalancerBackendSetParameters struct {

	// (Updatable) The health check policy configuration. For more information, see Editing Health Check Policies.
	// +kubebuilder:validation:Optional
	HealthChecker []HealthCheckerParameters `json:"healthChecker,omitempty" tf:"health_checker,omitempty"`

	// (Updatable) IP version associated with the backend set.
	// +kubebuilder:validation:Optional
	IPVersion *string `json:"ipVersion,omitempty" tf:"ip_version,omitempty"`

	// (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
	// +kubebuilder:validation:Optional
	IsFailOpen *bool `json:"isFailOpen,omitempty" tf:"is_fail_open,omitempty"`

	// (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
	// +kubebuilder:validation:Optional
	IsInstantFailoverEnabled *bool `json:"isInstantFailoverEnabled,omitempty" tf:"is_instant_failover_enabled,omitempty"`

	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	// +kubebuilder:validation:Optional
	IsPreserveSource *bool `json:"isPreserveSource,omitempty" tf:"is_preserve_source,omitempty"`

	// (Updatable) A read-only field showing the IP address/OCID and port that uniquely identify this backend server in the backend set.  Example: 10.0.0.3:8080, or ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:443 or 10.0.0.3:0
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The OCID of the network load balancer to update.
	// +kubebuilder:validation:Optional
	NetworkLoadBalancerID *string `json:"networkLoadBalancerId,omitempty" tf:"network_load_balancer_id,omitempty"`

	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE“
	// +kubebuilder:validation:Optional
	Policy *string `json:"policy,omitempty" tf:"policy,omitempty"`
}

// LoadBalancerBackendSetSpec defines the desired state of LoadBalancerBackendSet
type LoadBalancerBackendSetSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     LoadBalancerBackendSetParameters `json:"forProvider"`
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
	InitProvider LoadBalancerBackendSetInitParameters `json:"initProvider,omitempty"`
}

// LoadBalancerBackendSetStatus defines the observed state of LoadBalancerBackendSet.
type LoadBalancerBackendSetStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        LoadBalancerBackendSetObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LoadBalancerBackendSet is the Schema for the LoadBalancerBackendSets API. Provides the Backend Set resource in Oracle Cloud Infrastructure Network Load Balancer service
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,provider-oci}
type LoadBalancerBackendSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.healthChecker) || (has(self.initProvider) && has(self.initProvider.healthChecker))",message="spec.forProvider.healthChecker is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.networkLoadBalancerId) || (has(self.initProvider) && has(self.initProvider.networkLoadBalancerId))",message="spec.forProvider.networkLoadBalancerId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.policy) || (has(self.initProvider) && has(self.initProvider.policy))",message="spec.forProvider.policy is a required parameter"
	Spec   LoadBalancerBackendSetSpec   `json:"spec"`
	Status LoadBalancerBackendSetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LoadBalancerBackendSetList contains a list of LoadBalancerBackendSets
type LoadBalancerBackendSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LoadBalancerBackendSet `json:"items"`
}

// Repository type metadata.
var (
	LoadBalancerBackendSet_Kind             = "LoadBalancerBackendSet"
	LoadBalancerBackendSet_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: LoadBalancerBackendSet_Kind}.String()
	LoadBalancerBackendSet_KindAPIVersion   = LoadBalancerBackendSet_Kind + "." + CRDGroupVersion.String()
	LoadBalancerBackendSet_GroupVersionKind = CRDGroupVersion.WithKind(LoadBalancerBackendSet_Kind)
)

func init() {
	SchemeBuilder.Register(&LoadBalancerBackendSet{}, &LoadBalancerBackendSetList{})
}
