package policy

import (
	"time"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type PermissionRule struct {
	Permission               string
	RiskClass                string
	MaxTTL                   time.Duration
	MaxCacheStaleness        time.Duration
	RequiresAuthorizedDevice bool
}

type Engine struct {
	rules map[string]PermissionRule
}

func NewDefault() Engine {
	return Engine{rules: map[string]PermissionRule{
		"text":        {Permission: "text", RiskClass: "normal", MaxTTL: time.Hour, MaxCacheStaleness: 30 * time.Second, RequiresAuthorizedDevice: true},
		"audio.frame": {Permission: "audio.frame", RiskClass: "sensitive", MaxTTL: 5 * time.Minute, MaxCacheStaleness: 5 * time.Second, RequiresAuthorizedDevice: true},
	}}
}

func (e Engine) Rule(permission string) (PermissionRule, error) {
	rule, ok := e.rules[permission]
	if !ok {
		return PermissionRule{}, iscperrors.New(iscperrors.CodeTrustInvalid, "permission is not allowed by policy")
	}
	return rule, nil
}
