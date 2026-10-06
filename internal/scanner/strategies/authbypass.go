package strategies

import "github.com/Omkardalvi01/sentry/internal/model"

// AuthBypass is registered as phase two. Engine verifies paired authenticated
// and credential-free responses; findings alone cannot supply this evidence.
type AuthBypass struct{}

func (a *AuthBypass) Name() string { return model.StrategyAuthBypass }
