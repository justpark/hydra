package oauth2

import (
	"context"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/hydra/client"
)

type ResourceOwnerPasswordCredentialsGrantStorage interface {
	Authenticate(ctx context.Context, name string, secret string) (client.UserIdentityResponse, error)

	oauth2.AccessTokenStorage
	oauth2.RefreshTokenStorage
}
