package client

import (
	"encoding/json"
	"github.com/ory/fosite"
	"net/http"
	"net/url"
	"time"
)

type UserValidator struct {
	c    *http.Client
	conf Configuration
}

func NewUserValidator(conf Configuration) *UserValidator {
	return &UserValidator{
		c: &http.Client{
			Timeout: time.Second * 3,
		},
		conf: conf,
	}
}

func (v *UserValidator) Validate(username string, password string) (UserIdentityResponse, error) {
	formData := url.Values{
		"username": {username},
		"password": {password},
	}

	response, err := v.c.PostForm(v.conf.UserValidationURL().String(), formData)
	if err != nil || response.StatusCode != 200 {
		return UserIdentityResponse{}, fosite.ErrNotFound
	}

	userResponse := new(UserIdentityResponse)
	if err = json.NewDecoder(response.Body).Decode(userResponse); err != nil {
		return UserIdentityResponse{}, fosite.ErrNotFound
	}

	return *userResponse, nil
}
