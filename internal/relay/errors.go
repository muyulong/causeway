package relay

import "errors"

var (
	errDisabled = errors.New("server disabled")
	errBadToken = errors.New("bad token")
)
