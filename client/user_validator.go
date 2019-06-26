package client

import (
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

func (v *UserValidator) Validate(username string, password string) error {
	formData := url.Values{
		"username": {username},
		"password": {password},
	}

	_, err := v.c.PostForm(v.conf.UserValidationURL().String(), formData)
	if err != nil {
		return fosite.ErrNotFound
	}

	return nil
}
