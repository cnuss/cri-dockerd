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

package core

import (
	"github.com/Mirantis/cri-dockerd/config"
	"github.com/Mirantis/cri-dockerd/network/hostport"
)

// portMappingGetter is a wrapper around the dockerService that implements
// the network.PortMappingGetter interface.
type portMappingGetter struct {
	ds *dockerService
}

// namespaceGetter is a wrapper around the dockerService that implements
// the network.NamespaceGetter interface.
type namespaceGetter struct {
	ds *dockerService
}

func (n *namespaceGetter) GetNetNS(containerID string) (string, error) {
	return "", nil
}

func (p *portMappingGetter) GetPodPortMappings(
	containerID string,
) ([]*hostport.PortMapping, error) {
	return nil, nil
}

// dockerNetworkHost implements network.Host by wrapping the legacy host passed in by the kubelet
// and adding PortMapping support.
type dockerNetworkHost struct {
	*namespaceGetter
	*portMappingGetter
}

// effectiveHairpinMode determines the effective hairpin mode given the
// configured mode, and whether cbr0 should be configured.
func effectiveHairpinMode(s *config.NetworkPluginSettings) error {
	return nil
}
