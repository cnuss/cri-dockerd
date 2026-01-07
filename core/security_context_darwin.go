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
	"github.com/sirupsen/logrus"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func (ds *dockerService) getSecurityOpts(
	seccompProfile *v1.SecurityProfile,
	privileged bool,
	separator rune,
) ([]string, error) {
	if seccompProfile != nil {
		logrus.Info("seccomp annotations are not supported on darwin")
	}
	return nil, nil
}

func (ds *dockerService) getSandBoxSecurityOpts(separator rune) []string {
	// macOS Docker has limited security options compared to Linux
	// Return nil for now
	return nil
}
