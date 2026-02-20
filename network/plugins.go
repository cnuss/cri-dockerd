//go:build linux
// +build linux

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
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Mirantis/cri-dockerd/config"

	"github.com/sirupsen/logrus"
	utilsets "k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	utilexec "k8s.io/utils/exec"

	"github.com/Mirantis/cri-dockerd/network/hostport"
	"github.com/Mirantis/cri-dockerd/network/metrics"
	utilerrors "github.com/Mirantis/cri-dockerd/utils/errors"
)

// InitNetworkPlugin inits the plugin that matches networkPluginName. Plugins must have unique names.
func InitNetworkPlugin(
	plugins []NetworkPlugin,
	networkPluginName string,
	host Host,
	hairpinMode config.HairpinMode,
	nonMasqueradeCIDR string,
	mtu int,
) (NetworkPlugin, error) {
	if networkPluginName == "" || networkPluginName == "no-op" {
		// default to the no_op plugin
		plug := &NoopNetworkPlugin{}
		plug.Sysctl = utilsysctl.New()
		if err := plug.Init(host, hairpinMode, nonMasqueradeCIDR, mtu); err != nil {
			return nil, err
		}
		return plug, nil
	}

	pluginMap := map[string]NetworkPlugin{}

	allErrs := []error{}
	for _, plugin := range plugins {
		name := plugin.Name()
		if errs := validation.IsQualifiedName(name); len(errs) != 0 {
			allErrs = append(
				allErrs,
				fmt.Errorf(
					"network plugin has invalid name: %q: %s",
					name,
					strings.Join(errs, ";"),
				),
			)
			continue
		}

		if _, found := pluginMap[name]; found {
			allErrs = append(
				allErrs,
				fmt.Errorf("network plugin %q was registered more than once", name),
			)
			continue
		}
		pluginMap[name] = plugin
	}

	chosenPlugin := pluginMap[networkPluginName]
	if chosenPlugin != nil {
		err := chosenPlugin.Init(host, hairpinMode, nonMasqueradeCIDR, mtu)
		if err != nil {
			allErrs = append(
				allErrs,
				fmt.Errorf("network plugin %q failed init: %v", networkPluginName, err),
			)
		} else {
			logrus.Infof("Loaded network plugin %s", networkPluginName)
		}
	} else {
		allErrs = append(allErrs, fmt.Errorf("network plugin %q not found", networkPluginName))
	}

	return chosenPlugin, utilerrors.NewAggregate(allErrs)
}

type NoopNetworkPlugin struct {
	Sysctl utilsysctl.Interface
}

const sysctlBridgeCallIPTables = "net/bridge/bridge-nf-call-iptables"
const sysctlBridgeCallIP6Tables = "net/bridge/bridge-nf-call-ip6tables"

func (plugin *NoopNetworkPlugin) Init(
	host Host,
	hairpinMode config.HairpinMode,
	nonMasqueradeCIDR string,
	mtu int,
) error {
	// Set bridge-nf-call-iptables=1 to maintain compatibility with older
	// kubernetes versions to ensure the iptables-based kube proxy functions
	// correctly.  Other plugins are responsible for setting this correctly
	// depending on whether or not they connect containers to Linux bridges
	// or use some other mechanism (ie, SDN vswitch).

	// Ensure the netfilter module is loaded on kernel >= 3.18; previously
	// it was built-in.
	utilexec.New().Command("modprobe", "br-netfilter").CombinedOutput()
	if err := plugin.Sysctl.SetSysctl(sysctlBridgeCallIPTables, 1); err != nil {
		logrus.Errorf("can't set sysctl bridge-nf-call-iptables: %v", err)
	}
	if val, err := plugin.Sysctl.GetSysctl(sysctlBridgeCallIP6Tables); err == nil {
		if val != 1 {
			if err = plugin.Sysctl.SetSysctl(sysctlBridgeCallIP6Tables, 1); err != nil {
				logrus.Errorf("can't set sysctl bridge-nf-call-ip6tables: %v", err)
			}
		}
	}

	return nil
}

func (plugin *NoopNetworkPlugin) Event(name string, details map[string]interface{}) {
}

func (plugin *NoopNetworkPlugin) Name() string {
	return DefaultPluginName
}

func (plugin *NoopNetworkPlugin) Capabilities() utilsets.Int {
	return utilsets.NewInt()
}

func (plugin *NoopNetworkPlugin) SetUpPod(
	namespace string,
	name string,
	id config.ContainerID,
	annotations, options map[string]string,
) error {
	return nil
}

func (plugin *NoopNetworkPlugin) TearDownPod(
	namespace string,
	name string,
	id config.ContainerID,
) error {
	return nil
}

func (plugin *NoopNetworkPlugin) GetPodNetworkStatus(
	namespace string,
	name string,
	id config.ContainerID,
) (*PodNetworkStatus, error) {
	return nil, nil
}

func (plugin *NoopNetworkPlugin) Status() error {
	return nil
}

func getOnePodIP(
	execer utilexec.Interface,
	nsenterPath, netnsPath, interfaceName, addrType string,
) (net.IP, error) {
	// Try to retrieve ip inside container network namespace
	output, err := execer.Command(
		nsenterPath,
		fmt.Sprintf("--net=%s", netnsPath),
		"-F",
		"--",
		"ip",
		"-o",
		addrType,
		"addr",
		"show",
		"dev",
		interfaceName,
		"scope",
		"global",
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("unexpected command output %s with error: %v", output, err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("unexpected command output %s", output)
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 4 {
		return nil, fmt.Errorf("unexpected address output %s ", lines[0])
	}
	ip, _, err := net.ParseCIDR(fields[3])
	if err != nil {
		return nil, fmt.Errorf("CNI failed to parse ip from output %s due to %v", output, err)
	}

	return ip, nil
}

// GetPodIP gets the IP of the pod by inspecting the network info inside the pod's network namespace.
// we are defaulting to v4 as primary
func GetPodIPs(
	execer utilexec.Interface,
	nsenterPath, netnsPath, interfaceName string,
) ([]net.IP, error) {
	if !config.IPv6DualStackEnabled {
		ip, err := getOnePodIP(execer, nsenterPath, netnsPath, interfaceName, "-4")
		if err != nil {
			// Fall back to IPv6 address if no IPv4 address is present
			ip, err = getOnePodIP(execer, nsenterPath, netnsPath, interfaceName, "-6")
		}
		if err != nil {
			return nil, err
		}

		return []net.IP{ip}, nil
	}

	var (
		list []net.IP
		errs []error
	)
	for _, addrType := range []string{"-4", "-6"} {
		if ip, err := getOnePodIP(execer, nsenterPath, netnsPath, interfaceName, addrType); err == nil {
			list = append(list, ip)
		} else {
			errs = append(errs, err)
		}
	}

	if len(list) == 0 {
		return nil, utilerrors.NewAggregate(errs)
	}
	return list, nil

}

type NoopPortMappingGetter struct{}

func (*NoopPortMappingGetter) GetPodPortMappings(
	containerID string,
) ([]*hostport.PortMapping, error) {
	return nil, nil
}

// The PluginManager wraps a kubelet network plugin and provides synchronization
// for a given pod's network operations.  Each pod's setup/teardown/status operations
// are synchronized against each other, but network operations of other pods can
// proceed in parallel.
type PluginManager struct {
	// Network plugin being wrapped
	plugin NetworkPlugin

	// Pod list and lock
	podsLock sync.Mutex
	pods     map[string]*podLock
}

func NewPluginManager(plugin NetworkPlugin) *PluginManager {
	metrics.Register()
	return &PluginManager{
		plugin: plugin,
		pods:   make(map[string]*podLock),
	}
}

func (pm *PluginManager) PluginName() string {
	return pm.plugin.Name()
}

func (pm *PluginManager) Event(name string, details map[string]interface{}) {
	pm.plugin.Event(name, details)
}

func (pm *PluginManager) Status() error {
	return pm.plugin.Status()
}

type podLock struct {
	// Count of in-flight operations for this pod; when this reaches zero
	// the lock can be removed from the pod map
	refcount uint

	// Lock to synchronize operations for this specific pod
	mu sync.Mutex
}

// Lock network operations for a specific pod.  If that pod is not yet in
// the pod map, it will be added.  The reference count for the pod will
// be increased.
func (pm *PluginManager) podLock(fullPodName string) *sync.Mutex {
	pm.podsLock.Lock()
	defer pm.podsLock.Unlock()

	lock, ok := pm.pods[fullPodName]
	if !ok {
		lock = &podLock{}
		pm.pods[fullPodName] = lock
	}
	lock.refcount++
	return &lock.mu
}

// Unlock network operations for a specific pod.  The reference count for the
// pod will be decreased.  If the reference count reaches zero, the pod will be
// removed from the pod map.
func (pm *PluginManager) podUnlock(fullPodName string) {
	pm.podsLock.Lock()
	defer pm.podsLock.Unlock()

	lock, ok := pm.pods[fullPodName]
	if !ok {
		logrus.Debugf("Unbalanced pod lock unref for pod %s", fullPodName)
		return
	} else if lock.refcount == 0 {
		// This should never ever happen, but handle it anyway
		delete(pm.pods, fullPodName)
		logrus.Debugf("Pod lock for the pod still in map with zero refcount: %s", fullPodName)
		return
	}
	lock.refcount--
	lock.mu.Unlock()
	if lock.refcount == 0 {
		delete(pm.pods, fullPodName)
	}
}

// recordOperation records operation and duration
func recordOperation(operation string, start time.Time) {
	metrics.NetworkPluginOperations.WithLabelValues(operation).Inc()
	metrics.NetworkPluginOperationsLatency.WithLabelValues(
		operation,
	).Observe(
		metrics.SinceInSeconds(start),
	)
}

// recordError records errors for metric.
func recordError(operation string) {
	metrics.NetworkPluginOperationsErrors.WithLabelValues(operation).Inc()
}

func (pm *PluginManager) GetPodNetworkStatus(
	podNamespace, podName string,
	id config.ContainerID,
) (*PodNetworkStatus, error) {
	const operation = "get_pod_network_status"
	defer recordOperation(operation, time.Now())
	fullPodName := buildPodFullName(podName, podNamespace)
	pm.podLock(fullPodName).Lock()
	defer pm.podUnlock(fullPodName)

	netStatus, err := pm.plugin.GetPodNetworkStatus(podNamespace, podName, id)
	if err != nil {
		recordError(operation)
		return nil, fmt.Errorf(
			"networkPlugin %s failed on the status hook for pod %q: %v",
			pm.plugin.Name(),
			fullPodName,
			err,
		)
	}

	return netStatus, nil
}

func (pm *PluginManager) SetUpPod(
	podNamespace, podName string,
	id config.ContainerID,
	annotations, options map[string]string,
) error {
	const operation = "set_up_pod"
	defer recordOperation(operation, time.Now())
	fullPodName := buildPodFullName(podName, podNamespace)
	pm.podLock(fullPodName).Lock()
	defer pm.podUnlock(fullPodName)

	if err := pm.plugin.SetUpPod(podNamespace, podName, id, annotations, options); err != nil {
		recordError(operation)
		return fmt.Errorf(
			"networkPlugin %s failed to set up pod %q network: %v",
			pm.plugin.Name(),
			fullPodName,
			err,
		)
	}

	return nil
}

func (pm *PluginManager) TearDownPod(
	podNamespace, podName string,
	id config.ContainerID,
) error {
	const operation = "tear_down_pod"
	defer recordOperation(operation, time.Now())
	fullPodName := buildPodFullName(podName, podNamespace)
	pm.podLock(fullPodName).Lock()
	defer pm.podUnlock(fullPodName)

	if err := pm.plugin.TearDownPod(podNamespace, podName, id); err != nil {
		recordError(operation)
		return fmt.Errorf(
			"networkPlugin %s failed to teardown pod %q network: %v",
			pm.plugin.Name(),
			fullPodName,
			err,
		)
	}

	return nil
}

func buildPodFullName(name, namespace string) string {
	return name + "_" + namespace
}
