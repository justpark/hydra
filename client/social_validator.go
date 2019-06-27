package client

import (
	"github.com/ory/fosite"
	"net/http"
	"net/url"
	"time"
)

type SocialValidator struct {
	c    *http.Client
	conf Configuration
}

func NewSocialValidator(conf Configuration) *SocialValidator {
	return &SocialValidator{
		c: &http.Client{
			Timeout: time.Second * 3,
		},
		conf: conf,
	}
}

func (v *SocialValidator) Validate(network string, accessToken string) error {
	formData := url.Values{
		"network":      {network},
		"access_token": {accessToken},
	}

	response, err := v.c.PostForm(v.conf.SocialValidationURL().String(), formData)
	if err != nil || response.StatusCode != 200 {
		return fosite.ErrNotFound
	}

	return nil
}
