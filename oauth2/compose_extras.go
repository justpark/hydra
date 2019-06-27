package oauth2

import (
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

// OAuth2ResourceOwnerPasswordCredentialsFactory creates an OAuth2 resource owner password credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func ComposeSocialGrantFactory(config *compose.Config, storage interface{}, strategy interface{}) interface{} {
	return &SocialGrantHandler{
		SocialGrantStorage: storage.(SocialGrantStorage),
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy:  strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:   storage.(oauth2.AccessTokenStorage),
			AccessTokenLifespan:  config.GetAccessTokenLifespan(),
			RefreshTokenLifespan: config.GetRefreshTokenLifespan(),
		},
		RefreshTokenStrategy:     strategy.(oauth2.RefreshTokenStrategy),
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
	}
}
