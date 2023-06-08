package fleetservertest

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	APIKeyPrefix = "ApiKey "

	HeaderAuthorization = "Authorization"
)

type ctxKey struct{}

// APIKey is used to represent an APIKey and APIKeyID pair.
type APIKey struct {
	ID  string
	Key string
}

// APIKeyFromCtx returns the APIKey in the context or an empty APIKey if none is
// found.
func APIKeyFromCtx(ctx context.Context) APIKey {
	return ctx.Value(ctxKey{}).(APIKey)
}

func (a APIKey) WithCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
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
		return APIKey{}, errors.New("malformed authorization token")
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

	value := r.Header.Get(HeaderAuthorization)
	if value == "" {
		return APIKey{}, &HTTPError{
			StatusCode: http.StatusUnauthorized,
			Message:    "no authorization header",
		}
	}

	if !strings.HasPrefix(value, APIKeyPrefix) {
		return APIKey{}, &HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    "malformed authorization header",
		}
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
			Message:    "alid Handlers key: api key ID=" + apiKey.ID,
		}
	}

	return apiKey, nil
}

func AuthenticationMiddleware(key string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := Authenticate(r, key)
		if err != nil {
			respondAsJSON(err.StatusCode, err, w)
			return
		}

		rr := r.WithContext(apiKey.WithCtx(r.Context()))

		next.ServeHTTP(w, rr)
	})
}

// NewAuthorizationHeader returns a authorization header key-value pair built
// from key to be used to authenticate requests to Fleet Server.
//
//	req.Header.Set(NewAuthorizationHeader("my-api-key"))
func NewAuthorizationHeader(key string) (string, string) {
	v := base64.StdEncoding.EncodeToString([]byte("apiKeyID:" + key))

	return HeaderAuthorization, APIKeyPrefix + v
}
