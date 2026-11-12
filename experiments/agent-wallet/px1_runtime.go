package wallet

// PX1 stream S3 runtime (owner S3). STUBS until S3 lands.

import "context"

// px1Runtime holds S3's tracker, canary, float, alert and cached observation
// state. S2 adds exactly one field `px1 px1Runtime` to ActionService in
// service.go; S3 alone defines and mutates the content of this struct.
type px1Runtime struct{}

// PX1Enqueue registers a complete payment with the tracker.
func (s *ActionService) PX1Enqueue(p TrackedPayment) error { return ErrNotImplemented }

// PX1Tick runs one observation pass.
func (s *ActionService) PX1Tick(ctx context.Context) error { return ErrNotImplemented }

// PX1Status returns the status projection.
func (s *ActionService) PX1Status() (StatusProjectionV1, error) {
	return StatusProjectionV1{}, ErrNotImplemented
}
