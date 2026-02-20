//go:build !linux
// +build !linux

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

	"github.com/Mirantis/cri-dockerd/config"
	"github.com/Mirantis/cri-dockerd/network/hostport"

	utilsets "k8s.io/apimachinery/pkg/util/sets"
)

// NoopNetworkPlugin is a network plugin that does nothing (stub for non-Linux).
type NoopNetworkPlugin struct{}

func (plugin *NoopNetworkPlugin) Init(
	host Host,
	hairpinMode config.HairpinMode,
	nonMasqueradeCIDR string,
	mtu int,
) error {
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

// NoopPortMappingGetter is a port mapping getter that returns nothing.
type NoopPortMappingGetter struct{}

func (*NoopPortMappingGetter) GetPodPortMappings(
	containerID string,
) ([]*hostport.PortMapping, error) {
	return nil, nil
}

// InitNetworkPlugin is a stub for non-Linux platforms.
func InitNetworkPlugin(
	plugins []NetworkPlugin,
	networkPluginName string,
	host Host,
	hairpinMode config.HairpinMode,
	nonMasqueradeCIDR string,
	mtu int,
) (NetworkPlugin, error) {
	return &NoopNetworkPlugin{}, nil
}

// GetPodIPs is a stub for non-Linux platforms.
func GetPodIPs(
	execer interface{},
	nsenterPath, netnsPath, interfaceName string,
) ([]net.IP, error) {
	return nil, fmt.Errorf("GetPodIPs is not supported on this platform")
}

// PluginManager is a stub for non-Linux platforms.
type PluginManager struct {
	plugin NetworkPlugin
}

func NewPluginManager(plugin NetworkPlugin) *PluginManager {
	return &PluginManager{plugin: plugin}
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

func (pm *PluginManager) GetPodNetworkStatus(
	podNamespace, podName string,
	id config.ContainerID,
) (*PodNetworkStatus, error) {
	return pm.plugin.GetPodNetworkStatus(podNamespace, podName, id)
}

func (pm *PluginManager) SetUpPod(
	podNamespace, podName string,
	id config.ContainerID,
	annotations, options map[string]string,
) error {
	return pm.plugin.SetUpPod(podNamespace, podName, id, annotations, options)
}

func (pm *PluginManager) TearDownPod(
	podNamespace, podName string,
	id config.ContainerID,
) error {
	return pm.plugin.TearDownPod(podNamespace, podName, id)
}
