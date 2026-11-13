// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

// Failure is a local authority decision. The handler signs its public code;
// implementations must not embed credentials or application payloads in it.
type Failure struct {
	Code     string
	Revision *Counter
}

func (e *Failure) Error() string { return "control: " + e.Code }
