package oauth2

import (
	"context"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/hydra/client"
)

type SocialGrantStorage interface {
	SocialAuth(ctx context.Context, network string, accessToken string) (client.UserIdentityResponse, error)

	oauth2.AccessTokenStorage
	oauth2.RefreshTokenStorage
}
