// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	APIKeyPrefix = "ApiKey "

	HeaderAuthorization = "Authorization"
)

type ctxAuthKey struct{}

// APIKey is used to represent an APIKey and APIKeyID pair.
type APIKey struct {
	// ID is the ID of the API key to authenticate with Fleet Server
	ID string
	// Key is the API key to authenticate with Fleet Server.
	Key string
}

// String returns the APIKey as an "ID:Key" string.
func (k APIKey) String() string {
	return fmt.Sprintf("%s:%s", k.ID, k.Key)
}

// AuthFromCtx returns the APIKey the agent sent with the request or empty if
// none is found.
func AuthFromCtx(ctx context.Context) APIKey {
	return ctx.Value(ctxAuthKey{}).(APIKey)
}

func AuthWithCtx(ctx context.Context, a APIKey) context.Context {
	return context.WithValue(ctx, ctxAuthKey{}, a)
}

// NewAPIKey generates an APIKey from the given base 64 encoded auth and returns
// as *APIKey or an HTTPError if any error happens.
func NewAPIKey(auth string) (APIKey, error) {
	d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth))
	if err != nil {
		return APIKey{}, err
	}
	if !utf8.Valid(d) {
		return APIKey{}, errors.New("token is not valid utf8")
	}

	key := strings.Split(string(d), ":")
	if len(key) != 2 {
		return APIKey{}, fmt.Errorf("malformed authorization token: %q",
			key)
	}

	// interpret id:key
	apiKey := APIKey{
		ID:  key[0],
		Key: key[1],
	}

	return apiKey, nil
}

// Authenticate extracts the authentication from the HeaderAuthorization header
// and validates against key and returns:
// - an empty APIKey and an error if a key cannot be extracted,
// - the extracted APIKey and error if it does not match a.APIKey,
// - the extracted APIKey and a nil error if all succeeds.
func Authenticate(r *http.Request, key string) (APIKey, *HTTPError) {

	value, herr := getAuthorization(r)
	if herr != nil {
		return APIKey{}, herr
	}
	rawKey := value[len(APIKeyPrefix):]

	apiKey, err := NewAPIKey(rawKey)
	if err != nil {
		return APIKey{}, &HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
	}

	if apiKey.Key != key {
		return apiKey, &HTTPError{
			StatusCode: http.StatusUnauthorized,
			Message: fmt.Sprintf("invalid Handlers key: api key=%q, want %q",
				apiKey.Key, key),
		}
	}

	return apiKey, nil
}

func getAuthorization(r *http.Request) (string, *HTTPError) {
	value := r.Header.Get(HeaderAuthorization)
	if value == "" {
		return "", &HTTPError{
			StatusCode: http.StatusUnauthorized,
			Message:    "no authorization header",
		}
	}

	if !strings.HasPrefix(value, APIKeyPrefix) {
		return "", &HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    "malformed authorization header",
		}
	}

	return value, nil
}

// TODO: it does not work for enroll. Even though enroll and the other APIs
// authenticate using the same header, the way they handle the authentication
// is different. So it'd need to check the path and apply the right authentication.
func AuthenticationMiddleware(key string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := Authenticate(r, key)
		if err != nil {
			respondAsJSON(err.StatusCode, err, w)
			return
		}

		rr := r.WithContext(AuthWithCtx(r.Context(), apiKey))

		next.ServeHTTP(w, rr)
	})
}

// NewAuthorizationHeader returns an authorization header key-value pair built
// from key to be used to authenticate requests to Fleet Server.
//
//	req.Header.Set(NewAuthorizationHeader("my-api-key"))
func NewAuthorizationHeader(key string) (string, string) {
	v := base64.StdEncoding.EncodeToString([]byte("apiKeyID:" + key))

	return HeaderAuthorization, APIKeyPrefix + v
}
