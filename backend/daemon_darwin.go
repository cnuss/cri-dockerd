//go:build darwin
// +build darwin

package backend

import (
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

// listenFD returns an error on Darwin as systemd socket activation is not supported.
func listenFD(addr string) (net.Listener, error) {
	return nil, errors.New("socket activation (fd://) is not supported on Darwin; use unix:// or tcp:// instead")
}

// sdNotify is a no-op on Darwin as systemd is not available.
func sdNotify(state string) error {
	// No systemd on Darwin, silently ignore
	return nil
}

// handleNotify sets up signal handling for graceful shutdown on Darwin.
func handleNotify() {
	logrus.Debug("Setting up signal handlers (darwin mode - no systemd notification)")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		logrus.Infof("Received signal %v, shutting down", sig)
	}()
}
