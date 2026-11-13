// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import "time"

func (r Result) UsableUntil() time.Time {
	var expiry time.Time
	minimum := func(t time.Time) {
		if !t.IsZero() && (expiry.IsZero() || t.Before(expiry)) {
			expiry = t
		}
	}
	if g := r.Payload.Body.Grant; g != nil {
		minimum(g.ExpiresAt)
	}
	if creds := r.Payload.Body.RelayCredentials; creds != nil {
		minimum(creds.Access.ExpiresAt)
		minimum(creds.Refresh.ExpiresAt)
	}
	if child := r.Payload.Body.RelayResult; child != nil {
		minimum(child.UsableUntil())
	}
	return expiry
}
