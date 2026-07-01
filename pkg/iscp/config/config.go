package config

import (
	"os"
	"strings"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type Profile string

const (
	ProfileProduction Profile = "production"
	ProfileStaging    Profile = "staging"
	ProfileLocalLab   Profile = "local-lab"
)

type Gate struct {
	Profile                   Profile `json:"profile" yaml:"profile"`
	AllowUnsignedDescriptor   bool    `json:"allow_unsigned_descriptor" yaml:"allow_unsigned_descriptor"`
	AllowBearerOnlyAccess     bool    `json:"allow_bearer_only_access" yaml:"allow_bearer_only_access"`
	AllowPlaintextDebug       bool    `json:"allow_plaintext_debug" yaml:"allow_plaintext_debug"`
	AllowDebugSecrets         bool    `json:"allow_debug_secrets" yaml:"allow_debug_secrets"`
	RequireSignedDescriptors  bool    `json:"require_signed_descriptors" yaml:"require_signed_descriptors"`
	RequireProofOfPossession  bool    `json:"require_proof_of_possession" yaml:"require_proof_of_possession"`
	RequireSessionReadyBefore bool    `json:"require_session_ready_before_payload" yaml:"require_session_ready_before_payload"`
}

func DefaultGate(profile Profile) Gate {
	return Gate{
		Profile:                   profile,
		RequireSignedDescriptors:  profile != ProfileLocalLab,
		RequireProofOfPossession:  true,
		RequireSessionReadyBefore: true,
	}
}

func LoadProfileFromEnv(defaultProfile Profile) Profile {
	value := strings.TrimSpace(os.Getenv("ISCP_PROFILE"))
	if value == "" {
		return defaultProfile
	}
	return Profile(value)
}

func ValidateGate(g Gate) error {
	switch g.Profile {
	case ProfileProduction, ProfileStaging:
		if g.AllowUnsignedDescriptor {
			return iscperrors.New(iscperrors.CodeConfigInvalid, "profile forbids unsigned descriptors")
		}
		if g.AllowBearerOnlyAccess {
			return iscperrors.New(iscperrors.CodeConfigInvalid, "profile forbids bearer-only relay access")
		}
		if g.AllowPlaintextDebug || g.AllowDebugSecrets {
			return iscperrors.New(iscperrors.CodeConfigInvalid, "profile forbids plaintext debug secrets")
		}
	case ProfileLocalLab:
		if g.AllowPlaintextDebug && !g.AllowDebugSecrets {
			return iscperrors.New(iscperrors.CodeConfigInvalid, "plaintext debug requires allow_debug_secrets")
		}
	default:
		return iscperrors.New(iscperrors.CodeConfigInvalid, "unknown profile")
	}
	return nil
}
