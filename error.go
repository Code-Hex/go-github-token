package token

import "github.com/octokit/go-octokit/octokit"

type authError struct {
	err error
}

// Error for error interface
func (e *authError) Error() string {
	return e.err.Error()
}

// IsRequired2FACode check to require two factor code
func (e *authError) IsRequired2FACode() bool {
	resp, ok := e.err.(*octokit.ResponseError)
	return ok && resp.Type == octokit.ErrorOneTimePasswordRequired
}

// IsDuplicatedToken check if new token the same information as the previously created token
func (e *authError) IsDuplicatedToken() bool {
	resp, ok := e.err.(*octokit.ResponseError)
	return ok && resp.Type == octokit.ErrorUnprocessableEntity
}
