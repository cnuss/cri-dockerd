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

package hostport

import (
	"fmt"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/exec"
)

// clearConntrackEntriesForPort uses the conntrack CLI to clear entries for a given port.
func clearConntrackEntriesForPort(execer exec.Interface, port int, isIPv6 bool, protocol v1.Protocol) error {
	parameters := []string{"-D", "-p", strings.ToLower(string(protocol)), "--dport", strconv.Itoa(port)}
	if isIPv6 {
		parameters = append(parameters, "-f", "ipv6")
	}
	output, err := execer.Command("conntrack", parameters...).CombinedOutput()
	if err != nil && !strings.Contains(err.Error(), "No such file or directory") {
		// conntrack returns an error if no entries were found, which is acceptable
		if strings.Contains(string(output), "0 flow entries") {
			klog.V(4).InfoS("No conntrack entries found for port", "port", port, "protocol", protocol)
			return nil
		}
		return fmt.Errorf("error deleting conntrack entries for port %d: %v, output: %s", port, err, string(output))
	}
	klog.V(4).InfoS("Cleared conntrack entries for port", "port", port, "protocol", protocol, "output", string(output))
	return nil
}
