/*
Copyright 2021 Mirantis

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"net"

	"github.com/Mirantis/cri-dockerd/config"
	"github.com/Mirantis/cri-dockerd/network/hostport"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilsets "k8s.io/apimachinery/pkg/util/sets"
)

const (
	DefaultPluginName = "kubernetes.io/no-op"

	// Called when the node's Pod CIDR is known when using the
	// controller manager's --allocate-node-cidrs=true option
	NET_PLUGIN_EVENT_POD_CIDR_CHANGE             = "pod-cidr-change"
	NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR = "pod-cidr"
)

// NetworkPlugin is an interface to network plugins for the kubelet
type NetworkPlugin interface {
	// Init initializes the plugin.  This will be called exactly once
	// before any other methods are called.
	Init(host Host, hairpinMode config.HairpinMode, nonMasqueradeCIDR string, mtu int) error

	// Called on various events like:
	// NET_PLUGIN_EVENT_POD_CIDR_CHANGE
	Event(name string, details map[string]interface{})

	// Name returns the plugin's name. This will be used when searching
	// for a plugin by name, e.g.
	Name() string

	// Returns a set of NET_PLUGIN_CAPABILITY_*
	Capabilities() utilsets.Int

	// SetUpPod is the method called after the infra container of
	// the pod has been created but before the other containers of the
	// pod are launched.
	SetUpPod(
		namespace string,
		name string,
		podSandboxID config.ContainerID,
		annotations, options map[string]string,
	) error

	// TearDownPod is the method called before a pod's infra container will be deleted
	TearDownPod(namespace string, name string, podSandboxID config.ContainerID) error

	// GetPodNetworkStatus is the method called to obtain the ipv4 or ipv6 addresses of the container
	GetPodNetworkStatus(
		namespace string,
		name string,
		podSandboxID config.ContainerID,
	) (*PodNetworkStatus, error)

	// Status returns error if the network plugin is in error state
	Status() error
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/cmd/runtime.Object

// PodNetworkStatus stores the network status of a pod (currently just the primary IP address)
// This struct represents version "v1beta1"
type PodNetworkStatus struct {
	metav1.TypeMeta `json:",inline"`

	// IP is the primary ipv4/ipv6 address of the pod. Among other things it is the address that -
	//   - kube expects to be reachable across the cluster
	//   - service endpoints are constructed with
	//   - will be reported in the PodStatus.PodIP field (will override the IP reported by docker)
	IP net.IP `json:"ip"  description:"Primary IP address of the pod"`
	// IPs is the list of IPs assigned to Pod. IPs[0] == IP. The rest of the list is additional IPs
	IPs []net.IP `json:"ips" description:"list of additional ips (inclusive of IP) assigned to pod"`
}

// Host is an interface that plugins can use to access the kubelet.
// the back channel is restricted to host-ports/testing, and restricted
// to kubenet. No other network plugin wrapper needs it. Other plugins
// only require a way to access namespace information and port mapping
// information , which they can do directly through the embedded interfaces.
type Host interface {
	// NamespaceGetter is a getter for sandbox namespace information.
	NamespaceGetter

	// PortMappingGetter is a getter for sandbox port mapping information.
	PortMappingGetter
}

// NamespaceGetter is an interface to retrieve namespace information for a given
// podSandboxID. Typically implemented by runtime shims that are closely coupled to
// CNI plugin wrappers like kubenet.
type NamespaceGetter interface {
	// GetNetNS returns network namespace information for the given containerID.
	// Runtimes should *never* return an empty namespace and nil error for
	// a container; if error is nil then the namespace string must be valid.
	GetNetNS(containerID string) (string, error)
}

// PortMappingGetter is an interface to retrieve port mapping information for a given
// podSandboxID. Typically implemented by runtime shims that are closely coupled to
// CNI plugin wrappers like kubenet.
type PortMappingGetter interface {
	// GetPodPortMappings returns sandbox port mappings information.
	GetPodPortMappings(containerID string) ([]*hostport.PortMapping, error)
}
