package logging

import (
	"log/slog"
	"regexp"
	"strings"
)

var secretKeyPattern = regexp.MustCompile(`(?i)(private[_-]?key|refresh[_-]?credential|access[_-]?token|session[_-]?key|payload_plaintext|plaintext_payload|cipher_key|secret)`)

const redacted = "[REDACTED]"

func RedactKeyValue(key string, value any) any {
	if secretKeyPattern.MatchString(key) {
		return redacted
	}
	if s, ok := value.(string); ok {
		return RedactString(s)
	}
	return value
}

func RedactString(input string) string {
	lower := strings.ToLower(input)
	if strings.Contains(lower, "private key") ||
		strings.Contains(lower, "access_token=") ||
		strings.Contains(lower, "refresh_credential=") ||
		strings.Contains(lower, "session_key=") {
		return redacted
	}
	return input
}

func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	a.Value = slog.AnyValue(RedactKeyValue(a.Key, a.Value.Any()))
	return a
}
