package chaingateway

import "errors"

type readFailure string

func (e readFailure) Error() string { return "read refused" }
func failureClass(e error) string {
	if e == nil {
		return ""
	}
	var refusal readFailure
	if errors.As(e, &refusal) && (refusal == "tip_moved" || refusal == "rate_limited") {
		return string(refusal)
	}
	return "unavailable"
}
func strongerFailure(a, b error) error {
	rank := func(e error) int {
		switch failureClass(e) {
		case "":
			return 0
		case "tip_moved":
			return 1
		case "rate_limited":
			return 2
		default:
			return 3
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

type renamedError struct{ error }

func publicationRenamed(e error) bool { var r renamedError; return errors.As(e, &r) }
