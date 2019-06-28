package client_test

import (
	"github.com/ory/hydra/client"
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/internal"
	"github.com/spf13/viper"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNewUserValidator(t *testing.T) {
	type args struct {
		conf client.Configuration
	}
	tests := []struct {
		name string
		args args
		want *client.UserValidator
	}{
		{
			name: "test it instantiates a new configuration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := client.NewUserValidator(tt.args.conf); reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("NewUserValidator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserValidator_Validate(t *testing.T) {
	var payload string
	var statusCode = 200

	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(payload))
	}

	server := httptest.NewServer(h)
	defer server.Close()

	conf := internal.NewConfigurationWithDefaults()

	type fields struct {
		jsonResponse string
		conf         client.Configuration
	}
	type args struct {
		username string
		password string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       client.UserIdentityResponse
		wantErr    bool
		statusCode int
	}{
		{
			name: "it checks user credentials",
			fields: fields{
				jsonResponse: "{\"id\": \"1\"}",
			},
			args: args{
				username: "test",
				password: "password",
			},
			want: client.UserIdentityResponse{
				UserId: "1",
			},
			statusCode: 200,
		},
		{
			name:       "invalid status code will return error",
			statusCode: 401,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload = tt.fields.jsonResponse
			statusCode = tt.statusCode
			viper.Set(configuration.ViperKeyUserValidationURL, server.URL)

			v := client.NewUserValidatorWithHttp(conf, server.Client())
			got, err := v.Validate(tt.args.username, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("UserValidator.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UserValidator.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}
