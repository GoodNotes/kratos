// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"net/http"
	"net/url"

	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x/swagger"

	"github.com/gofrs/uuid"

	"github.com/ory/herodot"
)

// ErrNoActiveSessionFound is returned when no active cookie session could be found in the request.
type ErrNoActiveSessionFound struct {
	*herodot.DefaultError `json:"error"`

	// True when the request had no credentials in it.
	credentialsMissing bool
}

// NewErrNoActiveSessionFound creates a new ErrNoActiveSessionFound
func NewErrNoActiveSessionFound() *ErrNoActiveSessionFound {
	return &ErrNoActiveSessionFound{
		DefaultError: herodot.ErrUnauthorized.WithID(text.ErrNoActiveSession).WithError("request does not have a valid authentication session").WithReason("No active session was found in this request."),
	}
}

// NewErrNoCredentialsForSession creates a new NewErrNoCredentialsForSession
func NewErrNoCredentialsForSession() *ErrNoActiveSessionFound {
	e := NewErrNoActiveSessionFound()
	e.credentialsMissing = true
	return e
}

func (e *ErrNoActiveSessionFound) EnhanceJSONError() interface{} {
	return e
}

// Is returned when an active session was found but the requested AAL is not satisfied.
//
// swagger:model errorAuthenticatorAssuranceLevelNotSatisfied
//
//nolint:deadcode,unused
//lint:ignore U1000 Used to generate Swagger and OpenAPI definitions
type errorAuthenticatorAssuranceLevelNotSatisfied struct {
	Error swagger.GenericError `json:"error"`

	// Points to where to redirect the user to next.
	RedirectTo string `json:"redirect_browser_to"`
}

// ErrAALNotSatisfied is returned when an active session was found but the requested AAL is not satisfied.
type ErrAALNotSatisfied struct {
	*herodot.DefaultError `json:"error"`
	RedirectTo            string `json:"redirect_browser_to"`
}

func (e *ErrAALNotSatisfied) EnhanceJSONError() interface{} {
	return e
}

func (e *ErrAALNotSatisfied) PassReturnToAndLoginChallengeParameters(requestURL string) error {
	req, err := url.Parse(requestURL)
	if err != nil {
		return err
	}

	u, err := url.Parse(e.RedirectTo)
	if err != nil {
		return err
	}
	q := u.Query()

	hlc := req.Query().Get("login_challenge")
	if len(hlc) != 0 {
		q.Set("login_challenge", hlc)
	}

	returnTo := req.Query().Get("return_to")
	if len(returnTo) != 0 {
		q.Set("return_to", returnTo)
	}

	u.RawQuery = q.Encode()
	e.RedirectTo = u.String()

	return nil
}

// NewErrAALNotSatisfied creates a new ErrAALNotSatisfied.
func NewErrAALNotSatisfied(redirectTo string) *ErrAALNotSatisfied {
	return &ErrAALNotSatisfied{
		RedirectTo: redirectTo,
		DefaultError: &herodot.DefaultError{
			IDField:     text.ErrIDHigherAALRequired,
			StatusField: http.StatusText(http.StatusForbidden),
			ErrorField:  "Session does not fulfill the requested Authenticator Assurance Level",
			ReasonField: "An active session was found but it does not fulfill the requested Authenticator Assurance Level. Please verify yourself with a second factor to resolve this issue.",
			CodeField:   http.StatusForbidden,
			DetailsField: map[string]interface{}{
				"redirect_browser_to": redirectTo,
			},
		},
	}
}

// Manager handles identity sessions.
type Manager interface {
	// UpsertAndIssueCookie stores a session in the database and issues a cookie by calling IssueCookie.
	//
	// Also regenerates CSRF tokens due to assumed principal change.
	UpsertAndIssueCookie(context.Context, http.ResponseWriter, *http.Request, *Session) error

	// IssueCookie issues a cookie for the given session.
	//
	// Also regenerates CSRF tokens due to assumed principal change.
	IssueCookie(context.Context, http.ResponseWriter, *http.Request, *Session) error

	// RefreshCookie checks if the request uses an outdated cookie and refreshes the cookie if needed.
	RefreshCookie(context.Context, http.ResponseWriter, *http.Request, *Session) error

	// FetchFromRequest inspects the request cookies and retrieves the associated session from the database.
	FetchFromRequest(context.Context, *http.Request, ...Expandable) (*Session, error)

	// PurgeFromRequest removes an HTTP session.
	PurgeFromRequest(context.Context, http.ResponseWriter, *http.Request) error

	// DoesSessionSatisfy answers if a session is satisfying the AAL.
	DoesSessionSatisfy(r *http.Request, sess *Session, requestedAAL string, opts ...ManagerOptions) error

	// SessionAddAuthenticationMethods adds one or more authentication method to the session.
	SessionAddAuthenticationMethods(ctx context.Context, sid uuid.UUID, methods ...AuthenticationMethod) error

	// MaybeRedirectAPICodeFlow for API+Code flows redirects the user to the return_to URL and adds the code query parameter.
	// `handled` is true if the request a redirect was written, false otherwise.
	MaybeRedirectAPICodeFlow(w http.ResponseWriter, r *http.Request, f flow.Flow, sessionID uuid.UUID, uiNode node.UiNodeGroup) (handled bool, err error)
}

type ManagementProvider interface {
	SessionManager() Manager
}
