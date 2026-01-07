//go:build darwin
// +build darwin

package backend

import (
	"errors"
	"net"
)

func listenFD(addr string) (net.Listener, error) {
	return nil, errors.New("listening on a file descriptor is not supported on Darwin")
}

func handleNotify() {
}
