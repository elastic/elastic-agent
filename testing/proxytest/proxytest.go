package proxytest

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
)

func New() *httptest.Server {
	// address := ":0"
	// if os.address != "" {
	// 	address = os.address
	// }

	l, err := net.Listen("tcp", ":31416") //nolint:gosec // it's a test
	if err != nil {
		panic(fmt.Sprintf("NewServer failed to create a net.Listener: %v", err))
	}

	s := &httptest.Server{
		Listener: l,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bs, err := httputil.DumpRequest(r, true)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)

				msg := fmt.Sprintf("could not dump request: %#v\n", err)
				log.Print(msg)
				_, _ = fmt.Fprintf(w, msg)
				return

			}
			fmt.Println(string(bs))

			if r.URL.Scheme == "" {
				r.URL.Scheme = "http"
				if r.URL.Port() == "443" {
					r.URL.Scheme += "s"
				}
			}
			pr, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				msg := fmt.Sprintf("error creating request: %#v", err.Error())
				log.Print(msg)
				_, _ = fmt.Fprintf(w, msg)
				return
			}

			resp, err := http.DefaultClient.Do(pr)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				msg := fmt.Sprintf("could not make request: %#v", err.Error())
				log.Print(msg)
				_, _ = fmt.Fprint(w, msg)
				return
			}

			bs, err = httputil.DumpResponse(resp, true)
			if err != nil {
				fmt.Printf("could not dump response: %#v\n", err)
			}
			fmt.Println(string(bs))

			w.WriteHeader(resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = fmt.Fprintf(w, "could not read response body: %#v", err)
			}

			for k, v := range resp.Header {
				w.Header()[k] = v
			}
			// w.Header().
			_, _ = w.Write(body)
		})}}
	s.Start()

	return s
}
