// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/upjet/pkg/controller"

	containerconfiguration "github.com/rockchico/provider-oci/internal/controller/artifacts/containerconfiguration"
	containerrepository "github.com/rockchico/provider-oci/internal/controller/artifacts/containerrepository"
	genericartifact "github.com/rockchico/provider-oci/internal/controller/artifacts/genericartifact"
	repository "github.com/rockchico/provider-oci/internal/controller/artifacts/repository"
	managementcertificateauthority "github.com/rockchico/provider-oci/internal/controller/certificates/managementcertificateauthority"
	cluster "github.com/rockchico/provider-oci/internal/controller/containerengine/cluster"
	nodepool "github.com/rockchico/provider-oci/internal/controller/containerengine/nodepool"
	appcataloglistingresourceversionagreement "github.com/rockchico/provider-oci/internal/controller/core/appcataloglistingresourceversionagreement"
	appcatalogsubscription "github.com/rockchico/provider-oci/internal/controller/core/appcatalogsubscription"
	bootvolume "github.com/rockchico/provider-oci/internal/controller/core/bootvolume"
	bootvolumebackup "github.com/rockchico/provider-oci/internal/controller/core/bootvolumebackup"
	capturefilter "github.com/rockchico/provider-oci/internal/controller/core/capturefilter"
	clusternetwork "github.com/rockchico/provider-oci/internal/controller/core/clusternetwork"
	computecapacityreservation "github.com/rockchico/provider-oci/internal/controller/core/computecapacityreservation"
	computecluster "github.com/rockchico/provider-oci/internal/controller/core/computecluster"
	computeimagecapabilityschema "github.com/rockchico/provider-oci/internal/controller/core/computeimagecapabilityschema"
	consolehistory "github.com/rockchico/provider-oci/internal/controller/core/consolehistory"
	cpe "github.com/rockchico/provider-oci/internal/controller/core/cpe"
	crossconnect "github.com/rockchico/provider-oci/internal/controller/core/crossconnect"
	crossconnectgroup "github.com/rockchico/provider-oci/internal/controller/core/crossconnectgroup"
	dedicatedvmhost "github.com/rockchico/provider-oci/internal/controller/core/dedicatedvmhost"
	dhcpoptions "github.com/rockchico/provider-oci/internal/controller/core/dhcpoptions"
	drg "github.com/rockchico/provider-oci/internal/controller/core/drg"
	drgattachment "github.com/rockchico/provider-oci/internal/controller/core/drgattachment"
	drgattachmentmanagement "github.com/rockchico/provider-oci/internal/controller/core/drgattachmentmanagement"
	drgattachmentslist "github.com/rockchico/provider-oci/internal/controller/core/drgattachmentslist"
	drgroutedistribution "github.com/rockchico/provider-oci/internal/controller/core/drgroutedistribution"
	drgroutedistributionstatement "github.com/rockchico/provider-oci/internal/controller/core/drgroutedistributionstatement"
	drgroutetable "github.com/rockchico/provider-oci/internal/controller/core/drgroutetable"
	drgroutetablerouterule "github.com/rockchico/provider-oci/internal/controller/core/drgroutetablerouterule"
	image "github.com/rockchico/provider-oci/internal/controller/core/image"
	instance "github.com/rockchico/provider-oci/internal/controller/core/instance"
	instanceconfiguration "github.com/rockchico/provider-oci/internal/controller/core/instanceconfiguration"
	instanceconsoleconnection "github.com/rockchico/provider-oci/internal/controller/core/instanceconsoleconnection"
	instancepool "github.com/rockchico/provider-oci/internal/controller/core/instancepool"
	instancepoolinstance "github.com/rockchico/provider-oci/internal/controller/core/instancepoolinstance"
	internetgateway "github.com/rockchico/provider-oci/internal/controller/core/internetgateway"
	ipsec "github.com/rockchico/provider-oci/internal/controller/core/ipsec"
	ipsecconnectiontunnelmanagement "github.com/rockchico/provider-oci/internal/controller/core/ipsecconnectiontunnelmanagement"
	ipv6 "github.com/rockchico/provider-oci/internal/controller/core/ipv6"
	localpeeringgateway "github.com/rockchico/provider-oci/internal/controller/core/localpeeringgateway"
	natgateway "github.com/rockchico/provider-oci/internal/controller/core/natgateway"
	networksecuritygroup "github.com/rockchico/provider-oci/internal/controller/core/networksecuritygroup"
	networksecuritygroupsecurityrule "github.com/rockchico/provider-oci/internal/controller/core/networksecuritygroupsecurityrule"
	privateip "github.com/rockchico/provider-oci/internal/controller/core/privateip"
	publicip "github.com/rockchico/provider-oci/internal/controller/core/publicip"
	publicippool "github.com/rockchico/provider-oci/internal/controller/core/publicippool"
	publicippoolcapacity "github.com/rockchico/provider-oci/internal/controller/core/publicippoolcapacity"
	remotepeeringconnection "github.com/rockchico/provider-oci/internal/controller/core/remotepeeringconnection"
	routetable "github.com/rockchico/provider-oci/internal/controller/core/routetable"
	routetableattachment "github.com/rockchico/provider-oci/internal/controller/core/routetableattachment"
	securitylist "github.com/rockchico/provider-oci/internal/controller/core/securitylist"
	servicegateway "github.com/rockchico/provider-oci/internal/controller/core/servicegateway"
	shapemanagement "github.com/rockchico/provider-oci/internal/controller/core/shapemanagement"
	subnet "github.com/rockchico/provider-oci/internal/controller/core/subnet"
	vcn "github.com/rockchico/provider-oci/internal/controller/core/vcn"
	virtualcircuit "github.com/rockchico/provider-oci/internal/controller/core/virtualcircuit"
	vlan "github.com/rockchico/provider-oci/internal/controller/core/vlan"
	vnicattachment "github.com/rockchico/provider-oci/internal/controller/core/vnicattachment"
	volume "github.com/rockchico/provider-oci/internal/controller/core/volume"
	volumeattachment "github.com/rockchico/provider-oci/internal/controller/core/volumeattachment"
	volumebackup "github.com/rockchico/provider-oci/internal/controller/core/volumebackup"
	volumebackuppolicy "github.com/rockchico/provider-oci/internal/controller/core/volumebackuppolicy"
	volumebackuppolicyassignment "github.com/rockchico/provider-oci/internal/controller/core/volumebackuppolicyassignment"
	volumegroup "github.com/rockchico/provider-oci/internal/controller/core/volumegroup"
	volumegroupbackup "github.com/rockchico/provider-oci/internal/controller/core/volumegroupbackup"
	vtap "github.com/rockchico/provider-oci/internal/controller/core/vtap"
	record "github.com/rockchico/provider-oci/internal/controller/dns/record"
	resolver "github.com/rockchico/provider-oci/internal/controller/dns/resolver"
	resolverendpoint "github.com/rockchico/provider-oci/internal/controller/dns/resolverendpoint"
	rrset "github.com/rockchico/provider-oci/internal/controller/dns/rrset"
	steeringpolicy "github.com/rockchico/provider-oci/internal/controller/dns/steeringpolicy"
	steeringpolicyattachment "github.com/rockchico/provider-oci/internal/controller/dns/steeringpolicyattachment"
	tsigkey "github.com/rockchico/provider-oci/internal/controller/dns/tsigkey"
	view "github.com/rockchico/provider-oci/internal/controller/dns/view"
	zone "github.com/rockchico/provider-oci/internal/controller/dns/zone"
	rule "github.com/rockchico/provider-oci/internal/controller/events/rule"
	storageexport "github.com/rockchico/provider-oci/internal/controller/file/storageexport"
	storageexportset "github.com/rockchico/provider-oci/internal/controller/file/storageexportset"
	storagefilesystem "github.com/rockchico/provider-oci/internal/controller/file/storagefilesystem"
	storagemounttarget "github.com/rockchico/provider-oci/internal/controller/file/storagemounttarget"
	storagereplication "github.com/rockchico/provider-oci/internal/controller/file/storagereplication"
	storagesnapshot "github.com/rockchico/provider-oci/internal/controller/file/storagesnapshot"
	application "github.com/rockchico/provider-oci/internal/controller/functions/application"
	function "github.com/rockchico/provider-oci/internal/controller/functions/function"
	invokefunction "github.com/rockchico/provider-oci/internal/controller/functions/invokefunction"
	checkshttpmonitor "github.com/rockchico/provider-oci/internal/controller/health/checkshttpmonitor"
	checkspingmonitor "github.com/rockchico/provider-oci/internal/controller/health/checkspingmonitor"
	authenticationpolicy "github.com/rockchico/provider-oci/internal/controller/identity/authenticationpolicy"
	compartment "github.com/rockchico/provider-oci/internal/controller/identity/compartment"
	group "github.com/rockchico/provider-oci/internal/controller/identity/group"
	identityprovider "github.com/rockchico/provider-oci/internal/controller/identity/identityprovider"
	policy "github.com/rockchico/provider-oci/internal/controller/identity/policy"
	tag "github.com/rockchico/provider-oci/internal/controller/identity/tag"
	tagnamespace "github.com/rockchico/provider-oci/internal/controller/identity/tagnamespace"
	key "github.com/rockchico/provider-oci/internal/controller/kms/key"
	keyversion "github.com/rockchico/provider-oci/internal/controller/kms/keyversion"
	vault "github.com/rockchico/provider-oci/internal/controller/kms/vault"
	balancerbackend "github.com/rockchico/provider-oci/internal/controller/load/balancerbackend"
	balancerbackendset "github.com/rockchico/provider-oci/internal/controller/load/balancerbackendset"
	balancercertificate "github.com/rockchico/provider-oci/internal/controller/load/balancercertificate"
	balancerhostname "github.com/rockchico/provider-oci/internal/controller/load/balancerhostname"
	balancerlistener "github.com/rockchico/provider-oci/internal/controller/load/balancerlistener"
	balancerloadbalancer "github.com/rockchico/provider-oci/internal/controller/load/balancerloadbalancer"
	balancerloadbalancerroutingpolicy "github.com/rockchico/provider-oci/internal/controller/load/balancerloadbalancerroutingpolicy"
	balancerpathrouteset "github.com/rockchico/provider-oci/internal/controller/load/balancerpathrouteset"
	balancerruleset "github.com/rockchico/provider-oci/internal/controller/load/balancerruleset"
	balancersslciphersuite "github.com/rockchico/provider-oci/internal/controller/load/balancersslciphersuite"
	log "github.com/rockchico/provider-oci/internal/controller/logging/log"
	loggroup "github.com/rockchico/provider-oci/internal/controller/logging/loggroup"
	logsavedsearch "github.com/rockchico/provider-oci/internal/controller/logging/logsavedsearch"
	unifiedagentconfiguration "github.com/rockchico/provider-oci/internal/controller/logging/unifiedagentconfiguration"
	alarm "github.com/rockchico/provider-oci/internal/controller/monitoring/alarm"
	firewallnetworkfirewall "github.com/rockchico/provider-oci/internal/controller/network/firewallnetworkfirewall"
	firewallnetworkfirewallpolicy "github.com/rockchico/provider-oci/internal/controller/network/firewallnetworkfirewallpolicy"
	loadbalancerbackend "github.com/rockchico/provider-oci/internal/controller/network/loadbalancerbackend"
	loadbalancerbackendset "github.com/rockchico/provider-oci/internal/controller/network/loadbalancerbackendset"
	loadbalancerlistener "github.com/rockchico/provider-oci/internal/controller/network/loadbalancerlistener"
	loadbalancernetworkloadbalancer "github.com/rockchico/provider-oci/internal/controller/network/loadbalancernetworkloadbalancer"
	loadbalancernetworkloadbalancersbackendsetsunified "github.com/rockchico/provider-oci/internal/controller/network/loadbalancernetworkloadbalancersbackendsetsunified"
	bucket "github.com/rockchico/provider-oci/internal/controller/objectstorage/bucket"
	object "github.com/rockchico/provider-oci/internal/controller/objectstorage/object"
	objectlifecyclepolicy "github.com/rockchico/provider-oci/internal/controller/objectstorage/objectlifecyclepolicy"
	notificationtopic "github.com/rockchico/provider-oci/internal/controller/ons/notificationtopic"
	subscription "github.com/rockchico/provider-oci/internal/controller/ons/subscription"
	providerconfig "github.com/rockchico/provider-oci/internal/controller/providerconfig"
	meshaccesspolicy "github.com/rockchico/provider-oci/internal/controller/service/meshaccesspolicy"
	meshingressgateway "github.com/rockchico/provider-oci/internal/controller/service/meshingressgateway"
	meshingressgatewayroutetable "github.com/rockchico/provider-oci/internal/controller/service/meshingressgatewayroutetable"
	meshmesh "github.com/rockchico/provider-oci/internal/controller/service/meshmesh"
	meshvirtualdeployment "github.com/rockchico/provider-oci/internal/controller/service/meshvirtualdeployment"
	meshvirtualservice "github.com/rockchico/provider-oci/internal/controller/service/meshvirtualservice"
	meshvirtualserviceroutetable "github.com/rockchico/provider-oci/internal/controller/service/meshvirtualserviceroutetable"
	connectharness "github.com/rockchico/provider-oci/internal/controller/streaming/connectharness"
	stream "github.com/rockchico/provider-oci/internal/controller/streaming/stream"
	streampool "github.com/rockchico/provider-oci/internal/controller/streaming/streampool"
	secret "github.com/rockchico/provider-oci/internal/controller/vault/secret"
)

// Setup creates all controllers with the supplied logger and adds them to
// the supplied manager.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	for _, setup := range []func(ctrl.Manager, controller.Options) error{
		containerconfiguration.Setup,
		containerrepository.Setup,
		genericartifact.Setup,
		repository.Setup,
		managementcertificateauthority.Setup,
		cluster.Setup,
		nodepool.Setup,
		appcataloglistingresourceversionagreement.Setup,
		appcatalogsubscription.Setup,
		bootvolume.Setup,
		bootvolumebackup.Setup,
		capturefilter.Setup,
		clusternetwork.Setup,
		computecapacityreservation.Setup,
		computecluster.Setup,
		computeimagecapabilityschema.Setup,
		consolehistory.Setup,
		cpe.Setup,
		crossconnect.Setup,
		crossconnectgroup.Setup,
		dedicatedvmhost.Setup,
		dhcpoptions.Setup,
		drg.Setup,
		drgattachment.Setup,
		drgattachmentmanagement.Setup,
		drgattachmentslist.Setup,
		drgroutedistribution.Setup,
		drgroutedistributionstatement.Setup,
		drgroutetable.Setup,
		drgroutetablerouterule.Setup,
		image.Setup,
		instance.Setup,
		instanceconfiguration.Setup,
		instanceconsoleconnection.Setup,
		instancepool.Setup,
		instancepoolinstance.Setup,
		internetgateway.Setup,
		ipsec.Setup,
		ipsecconnectiontunnelmanagement.Setup,
		ipv6.Setup,
		localpeeringgateway.Setup,
		natgateway.Setup,
		networksecuritygroup.Setup,
		networksecuritygroupsecurityrule.Setup,
		privateip.Setup,
		publicip.Setup,
		publicippool.Setup,
		publicippoolcapacity.Setup,
		remotepeeringconnection.Setup,
		routetable.Setup,
		routetableattachment.Setup,
		securitylist.Setup,
		servicegateway.Setup,
		shapemanagement.Setup,
		subnet.Setup,
		vcn.Setup,
		virtualcircuit.Setup,
		vlan.Setup,
		vnicattachment.Setup,
		volume.Setup,
		volumeattachment.Setup,
		volumebackup.Setup,
		volumebackuppolicy.Setup,
		volumebackuppolicyassignment.Setup,
		volumegroup.Setup,
		volumegroupbackup.Setup,
		vtap.Setup,
		record.Setup,
		resolver.Setup,
		resolverendpoint.Setup,
		rrset.Setup,
		steeringpolicy.Setup,
		steeringpolicyattachment.Setup,
		tsigkey.Setup,
		view.Setup,
		zone.Setup,
		rule.Setup,
		storageexport.Setup,
		storageexportset.Setup,
		storagefilesystem.Setup,
		storagemounttarget.Setup,
		storagereplication.Setup,
		storagesnapshot.Setup,
		application.Setup,
		function.Setup,
		invokefunction.Setup,
		checkshttpmonitor.Setup,
		checkspingmonitor.Setup,
		authenticationpolicy.Setup,
		compartment.Setup,
		group.Setup,
		identityprovider.Setup,
		policy.Setup,
		tag.Setup,
		tagnamespace.Setup,
		key.Setup,
		keyversion.Setup,
		vault.Setup,
		balancerbackend.Setup,
		balancerbackendset.Setup,
		balancercertificate.Setup,
		balancerhostname.Setup,
		balancerlistener.Setup,
		balancerloadbalancer.Setup,
		balancerloadbalancerroutingpolicy.Setup,
		balancerpathrouteset.Setup,
		balancerruleset.Setup,
		balancersslciphersuite.Setup,
		log.Setup,
		loggroup.Setup,
		logsavedsearch.Setup,
		unifiedagentconfiguration.Setup,
		alarm.Setup,
		firewallnetworkfirewall.Setup,
		firewallnetworkfirewallpolicy.Setup,
		loadbalancerbackend.Setup,
		loadbalancerbackendset.Setup,
		loadbalancerlistener.Setup,
		loadbalancernetworkloadbalancer.Setup,
		loadbalancernetworkloadbalancersbackendsetsunified.Setup,
		bucket.Setup,
		object.Setup,
		objectlifecyclepolicy.Setup,
		notificationtopic.Setup,
		subscription.Setup,
		providerconfig.Setup,
		meshaccesspolicy.Setup,
		meshingressgateway.Setup,
		meshingressgatewayroutetable.Setup,
		meshmesh.Setup,
		meshvirtualdeployment.Setup,
		meshvirtualservice.Setup,
		meshvirtualserviceroutetable.Setup,
		connectharness.Setup,
		stream.Setup,
		streampool.Setup,
		secret.Setup,
	} {
		if err := setup(mgr, o); err != nil {
			return err
		}
	}
	return nil
}
