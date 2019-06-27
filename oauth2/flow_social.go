package oauth2

import (
	"context"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/pkg/errors"
	"time"
)

// Added social grant by @daursu
type SocialGrantHandler struct {
	// SocialGrantStorage is used to persist session data across requests.
	SocialGrantStorage SocialGrantStorage

	RefreshTokenStrategy     oauth2.RefreshTokenStrategy
	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy

	*oauth2.HandleHelper
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *SocialGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "social".
	if !request.GetGrantTypes().Exact("social") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("social") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithHint("The client is not allowed to use authorization grant \"social\"."))
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope \"%s\".", scope))
		}
	}

	if err := c.AudienceMatchingStrategy(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	network := request.GetRequestForm().Get("network")
	accessToken := request.GetRequestForm().Get("access_token")
	if network == "" || accessToken == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHint("Network or access_token are missing from the POST body."))
	}

	// Attempt to log the user in
	userIdentity, err := c.SocialGrantStorage.SocialAuth(ctx, network, accessToken)

	if errors.Cause(err) == fosite.ErrNotFound {
		return errors.WithStack(fosite.ErrRequestUnauthorized.WithHint("Unable to authenticate the provided network and access_token credentials.").WithDebug(err.Error()))
	} else if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	// Credentials must not be passed around, potentially leaking to the database!
	delete(request.GetRequestForm(), "access_token")

	// Update the username to be the UserId
	session := request.GetSession().(*Session)
	session.Username = userIdentity.UserId
	session.Claims.Subject = userIdentity.UserId
	session.Claims.Add("properties", userIdentity)

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan).Round(time.Second))
	if c.RefreshTokenLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *SocialGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("social") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	var refresh, refreshSignature string
	if requester.GetGrantedScopes().HasOneOf("offline", "offline_access") {
		var err error
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		} else if err := c.SocialGrantStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
	}

	if err := c.IssueAccessToken(ctx, requester, responder); err != nil {
		return err
	}

	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	return nil
}
