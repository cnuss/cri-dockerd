//go:build !darwin
// +build !darwin

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

// applyDNSConfig is a no-op on non-darwin platforms.
// DNS configuration is handled by rewriting resolv.conf after container creation.
func applyDNSConfig(createConfig *dockerbackend.ContainerCreateConfig, dnsConfig *runtimeapi.DNSConfig) {
	// No-op on Linux/Windows - DNS is handled via resolv.conf rewriting
}

// shouldRewriteResolvConf returns whether we should attempt to rewrite
// the resolv.conf file after container creation.
// On Linux and Windows, this returns true.
func shouldRewriteResolvConf() bool {
	return true
}
