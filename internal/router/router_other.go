//go:build !darwin && !linux && !windows

package router

func newOSRouter(cfg Config) (Router, error) {
	return newDummyRouter(cfg), nil
}
