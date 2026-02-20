//go:build darwin
// +build darwin

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
	dockerbackend "github.com/docker/docker/api/types/backend"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// applyDNSConfig applies DNS configuration to the container create config.
// On Darwin with Docker Desktop, we pass DNS config directly to Docker
// since the resolv.conf path inside the VM is not accessible from the host.
func applyDNSConfig(createConfig *dockerbackend.ContainerCreateConfig, dnsConfig *runtimeapi.DNSConfig) {
	if dnsConfig == nil {
		return
	}
	if len(dnsConfig.Servers) > 0 {
		createConfig.HostConfig.DNS = dnsConfig.Servers
	}
	if len(dnsConfig.Searches) > 0 {
		createConfig.HostConfig.DNSSearch = dnsConfig.Searches
	}
	if len(dnsConfig.Options) > 0 {
		createConfig.HostConfig.DNSOptions = dnsConfig.Options
	}
}

// shouldRewriteResolvConf returns whether we should attempt to rewrite
// the resolv.conf file after container creation.
// On Darwin with Docker Desktop, the resolv.conf path is inside the VM
// and not accessible from the host, so we return false.
func shouldRewriteResolvConf() bool {
	return false
}
