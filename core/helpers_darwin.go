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
	"fmt"

	"github.com/blang/semver"
	dockertypes "github.com/docker/docker/api/types"
	dockerbackend "github.com/docker/docker/api/types/backend"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// DefaultMemorySwap returns -1 for no memory swap in a sandbox on Darwin.
// Docker Desktop handles memory management through its VM.
func DefaultMemorySwap() int64 {
	return -1
}

func (ds *dockerService) updateCreateConfig(
	createConfig *dockerbackend.ContainerCreateConfig,
	config *runtimeapi.ContainerConfig,
	sandboxConfig *runtimeapi.PodSandboxConfig,
	podSandboxID string, securityOptSep rune, apiVersion *semver.Version) error {
	// Apply Linux-specific options if applicable.
	// On Darwin with Docker Desktop, these are passed to the Linux VM.
	if lc := config.GetLinux(); lc != nil {
		rOpts := lc.GetResources()
		if rOpts != nil {
			createConfig.HostConfig.Resources = dockercontainer.Resources{
				Memory:     rOpts.MemoryLimitInBytes,
				MemorySwap: rOpts.MemoryLimitInBytes,
				CPUShares:  rOpts.CpuShares,
				CPUQuota:   rOpts.CpuQuota,
				CPUPeriod:  rOpts.CpuPeriod,
				CpusetCpus: rOpts.CpusetCpus,
				CpusetMems: rOpts.CpusetMems,
			}
			createConfig.HostConfig.OomScoreAdj = int(rOpts.OomScoreAdj)
		}

		// Apply security context - delegated to Docker Desktop's Linux VM
		if err := applyContainerSecurityContext(lc, podSandboxID, createConfig.Config, createConfig.HostConfig, securityOptSep); err != nil {
			return fmt.Errorf(
				"failed to apply container security context for container %q: %v",
				config.Metadata.Name,
				err,
			)
		}
	}

	// Apply cgroupsParent derived from the sandbox config.
	// Docker Desktop handles cgroups in its Linux VM.
	if lc := sandboxConfig.GetLinux(); lc != nil {
		cgroupParent, err := ds.GenerateExpectedCgroupParent(lc.CgroupParent)
		if err != nil {
			return fmt.Errorf(
				"failed to generate cgroup parent in expected syntax for container %q: %v",
				config.Metadata.Name,
				err,
			)
		}
		createConfig.HostConfig.CgroupParent = cgroupParent
	}

	return nil
}

func (ds *dockerService) determinePodIPBySandboxID(uid string) []string {
	// On Darwin, networking is managed by Docker Desktop
	return nil
}

func getNetworkNamespace(c *dockertypes.ContainerJSON) (string, error) {
	// On Darwin with Docker Desktop, containers run in a Linux VM.
	// The network namespace path format follows Linux conventions,
	// but the actual namespace is inside the VM.
	if c.State.Pid == 0 {
		return "", fmt.Errorf("cannot find network namespace for the terminated container %q", c.ID)
	}
	// Return the Linux-style path - Docker Desktop handles the translation
	return fmt.Sprintf(dockerNetNSFmt, c.State.Pid), nil
}

type containerCleanupInfo struct{}

func (ds *dockerService) applyPlatformSpecificDockerConfig(
	*runtimeapi.CreateContainerRequest,
	*dockerbackend.ContainerCreateConfig,
) (*containerCleanupInfo, error) {
	return nil, nil
}

func (ds *dockerService) performPlatformSpecificContainerCleanup(
	cleanupInfo *containerCleanupInfo,
) (errors []error) {
	return
}

func (ds *dockerService) platformSpecificContainerInitCleanup() (errors []error) {
	return
}

func (ds *dockerService) performPlatformSpecificContainerForContainer(
	containerID string,
) (errors []error) {
	if cleanupInfo, present := ds.getContainerCleanupInfo(containerID); present {
		errors = ds.performPlatformSpecificContainerCleanupAndLogErrors(containerID, cleanupInfo)

		if len(errors) == 0 {
			ds.clearContainerCleanupInfo(containerID)
		}
	}

	return
}

func (ds *dockerService) performPlatformSpecificContainerCleanupAndLogErrors(
	containerNameOrID string,
	cleanupInfo *containerCleanupInfo,
) []error {
	if cleanupInfo == nil {
		return nil
	}

	errors := ds.performPlatformSpecificContainerCleanup(cleanupInfo)
	for _, err := range errors {
		logrus.Infof("Error when cleaning up after container %s: %v", containerNameOrID, err)
	}

	return errors
}
