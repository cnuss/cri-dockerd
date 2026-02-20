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
	"syscall"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/sirupsen/logrus"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// imageFsInfo returns information of the filesystem of docker data root.
// On Darwin with Docker Desktop, the Docker root directory (/var/lib/docker)
// is inside the Linux VM and not directly accessible from the host.
// We skip filesystem stats and only report image sizes from the Docker API.
func (ds *dockerService) imageFsInfo() (*runtimeapi.ImageFsInfoResponse, error) {
	var usedBytes uint64
	var iNodesUsed uint64

	// Try to get filesystem stats, but don't fail if the path is inside Docker Desktop's VM
	stat := &syscall.Statfs_t{}
	err := syscall.Statfs(ds.dockerRootDir, stat)
	if err != nil {
		// On Docker Desktop, /var/lib/docker is inside the VM and not accessible
		logrus.Debugf("Cannot stat Docker root dir %s (expected on Docker Desktop): %v", ds.dockerRootDir, err)
		// Continue without filesystem stats - we'll still report image sizes
	} else {
		usedBytes = (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)
		iNodesUsed = stat.Files - stat.Ffree
		logrus.Debugf("Filesystem usage containing '%s': usedBytes=%v, iNodesUsed=%v", ds.dockerRootDir, usedBytes, iNodesUsed)
	}

	// compute total used bytes by docker images
	images, err := ds.client.ListImages(image.ListOptions{All: true, SharedSize: true})
	if err != nil {
		logrus.Errorf("Failed to get image list from docker: %v", err)
		return nil, err
	}
	var totalImageSize uint64
	sharedSizeMap := make(map[int64]struct{})
	for _, i := range images {
		if i.SharedSize == -1 {
			totalImageSize += uint64(i.Size)
		} else { // docker version >= 23.0
			totalImageSize += (uint64(i.Size) - uint64(i.SharedSize))
			sharedSizeMap[i.SharedSize] = struct{}{}
		}
	}
	for k := range sharedSizeMap {
		totalImageSize += uint64(k)
	}
	logrus.Debugf("Total used bytes by docker images: %v", totalImageSize)

	return &runtimeapi.ImageFsInfoResponse{
		ImageFilesystems: []*runtimeapi.FilesystemUsage{
			{
				Timestamp: time.Now().UnixNano(),
				FsId: &runtimeapi.FilesystemIdentifier{
					Mountpoint: ds.dockerRootDir,
				},
				UsedBytes: &runtimeapi.UInt64Value{
					Value: totalImageSize,
				},
				InodesUsed: &runtimeapi.UInt64Value{
					Value: iNodesUsed,
				},
			}},
		ContainerFilesystems: []*runtimeapi.FilesystemUsage{
			{
				Timestamp: time.Now().UnixNano(),
				FsId: &runtimeapi.FilesystemIdentifier{
					Mountpoint: ds.dockerRootDir,
				},
				UsedBytes: &runtimeapi.UInt64Value{
					Value: ds.containerStatsCache.getWriteableLayer(),
				},
			}},
	}, nil
}
