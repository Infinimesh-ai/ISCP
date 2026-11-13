package relay

import (
	"net/http"
)

func (s *Server) MarkRevoked(deviceID string) {
	s.InvalidateDevice(deviceID)
	s.mu.Lock()
	s.revoked[deviceID] = struct{}{}
	s.mu.Unlock()
}

func managedStatus(err error) int {
	if v, ok := err.(interface{ StatusCode() int }); ok {
		return v.StatusCode()
	}
	return http.StatusServiceUnavailable
}

// InvalidateDevice discards credential/identity caches only after the durable
// transaction commits. The next request checks the repository's current state.
func (s *Server) InvalidateDevice(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.access {
		if c.DeviceID == deviceID {
			delete(s.access, k)
		}
	}
	for k, c := range s.refresh {
		if c.DeviceID == deviceID {
			delete(s.refresh, k)
		}
	}
	delete(s.devices, deviceID)
}
