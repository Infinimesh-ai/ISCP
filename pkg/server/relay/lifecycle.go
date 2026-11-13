package relay

func receiveKey(domain, device string) string { return domain + "\x00" + device }

// Close cancels and joins all duplex sockets and cleanup owned by this server.
// HTTP server shutdown alone does not close upgraded WebSockets.
func (s *Server) Close() {
	s.duplexMu.Lock()
	s.duplexClosed = true
	if s.maintenanceCancel != nil {
		s.maintenanceCancel()
	}
	for c := range s.duplexAll {
		c.cancel()
		_ = c.ws.Close()
	}
	s.duplexMu.Unlock()
	s.duplexWG.Wait()
}
