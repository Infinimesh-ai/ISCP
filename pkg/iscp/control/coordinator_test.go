// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"
	"testing"
)

func TestCoordinatorRequiresConsumerVerificationBeforeAnyIO(t *testing.T) {
	c := &Coordinator{}
	if _, err := c.Result(context.Background(), "relay.refresh"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing verifier: %v", err)
	}
	if err := c.Installed(context.Background(), RandomID()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing verifier: %v", err)
	}
}
