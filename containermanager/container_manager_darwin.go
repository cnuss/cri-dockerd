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

package containermanager

import (
	"github.com/Mirantis/cri-dockerd/libdocker"
	"github.com/sirupsen/logrus"
)

// NewContainerManager creates a new instance of ContainerManager
func NewContainerManager(cgroupsName string, client libdocker.DockerClientInterface) ContainerManager {
	return &darwinContainerManager{
		cgroupsName: cgroupsName,
		client:      client,
	}
}

type darwinContainerManager struct {
	client      libdocker.DockerClientInterface
	cgroupsName string
}

// Start is a no-op on Darwin. Docker Desktop manages container resources
// through its VM, so cgroup management is not needed.
func (m *darwinContainerManager) Start() error {
	logrus.Info("Container manager starting (darwin mode - cgroup management delegated to Docker Desktop)")
	return nil
}
