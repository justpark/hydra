package oauth2

import (
	"context"
	"github.com/ory/fosite/handler/oauth2"
)

type SocialGrantStorage interface {
	SocialAuth(ctx context.Context, network string, accessToken string) error

	oauth2.AccessTokenStorage
	oauth2.RefreshTokenStorage
}
