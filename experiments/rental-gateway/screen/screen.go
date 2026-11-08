// Package screen is the gateway's boundary to the screening model.
// The model can only refuse: the gateway delivers only on an explicit
// Allow, and maps errors, timeouts and malformed answers to refusal.
package screen

import (
	"context"
	"fmt"
	"strings"
)

// Decision is a screening outcome. Allow=false with a Reason is a
// refusal. There is no third state.
type Decision struct {
	Allow  bool
	Reason string
}

// Screener screens one inbound message content. Implementations must
// respect ctx; the gateway additionally enforces a hard timeout, so a
// stuck screener still ends in refusal, never delivery.
type Screener interface {
	Screen(ctx context.Context, content string) (Decision, error)
}

// Stub is a scripted screener for tests: it refuses contents
// containing any RefuseSubstrings entry, allows everything else,
// unless Handler or Err says otherwise.
type Stub struct {
	RefuseSubstrings []string
	Reason           string
	Err              error
	Handler          func(ctx context.Context, content string) (Decision, error)
	Calls            int
}

// Screen implements Screener.
func (s *Stub) Screen(ctx context.Context, content string) (Decision, error) {
	s.Calls++
	if s.Handler != nil {
		return s.Handler(ctx, content)
	}
	if s.Err != nil {
		return Decision{Allow: false}, s.Err
	}
	for _, bad := range s.RefuseSubstrings {
		if strings.Contains(content, bad) {
			r := s.Reason
			if r == "" {
				r = "screening refusal"
			}
			return Decision{Allow: false, Reason: r}, nil
		}
	}
	return Decision{Allow: true}, nil
}

// ParseAnswer converts a model text answer to a Decision. Only the
// exact first tokens "ALLOW" / "REFUSE <reason>" are well-formed;
// anything else is an error, which the gateway treats as refusal.
func ParseAnswer(answer string) (Decision, error) {
	a := strings.TrimSpace(answer)
	switch {
	case a == "ALLOW":
		return Decision{Allow: true}, nil
	case strings.HasPrefix(a, "REFUSE "):
		reason := strings.TrimSpace(strings.TrimPrefix(a, "REFUSE "))
		if reason == "" {
			return Decision{}, fmt.Errorf("screening answer: REFUSE without reason")
		}
		return Decision{Allow: false, Reason: reason}, nil
	default:
		return Decision{}, fmt.Errorf("screening answer: malformed")
	}
}
