package main

import (
	"net/http"

	"github.com/rs/zerolog"
)

func RequestFields(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context())

		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			c = c.Stringer("url", r.URL)
			c = c.Str("method", r.Method)
			c = c.Str("ip", r.RemoteAddr)
			// c = c.Str("user_agent", r.UserAgent())
			return c
		})

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
