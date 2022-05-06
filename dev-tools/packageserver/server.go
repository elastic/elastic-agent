package packageserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	zlog "github.com/rs/zerolog/log"
)

// StartServer starts the HTTP server to serve the beats, it accepts 3 arguments:
// Beats source directory, a folder to store/serve the packaged Beats and a port to run
func StartServer(sourceDir, storageDir string, httpPort int) {
	// Build from x-pack by default, we can make it configurable later
	sourceDir = filepath.Join(sourceDir, "x-pack")

	logger := zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Replace the global logger
	log.SetFlags(0)
	log.SetOutput(logger)

	r := chi.NewRouter()

	r.Use(hlog.NewHandler(logger))
	r.Use(hlog.RequestIDHandler("req_id", "Request-Id"))
	r.Use(requestFields)
	r.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		zerolog.Ctx(r.Context()).Info().
			Int("status", status).
			Int("size", size).
			Dur("duration_ms", duration).
			Msg("")
	}))

	r.Get("/beats/{beatName}/*", handleBeats(sourceDir, storageDir))

	// Create a route along /files that will serve contents from
	// the ./data/ folder.
	filesDir := http.Dir(storageDir)
	fileServer(r, "/files", filesDir)

	addr := fmt.Sprintf(":%d", httpPort)
	logger.Info().Msgf("starting server on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		panic(err)
	}
}

func handleBeats(sourceDir, storageDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		split := strings.Split(r.URL.Path, "/")
		filename := split[len(split)-1]

		switch {
		case strings.HasSuffix(filename, ".sha512"):
			fullPath := path.Join("/files", filename)
			http.Redirect(w, r, fullPath, http.StatusTemporaryRedirect)

		case strings.HasSuffix(filename, ".tar.gz"):
			halderZip := handlerPackageBeats(sourceDir, storageDir, filename)
			halderZip(w, r)

		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "cannot handle %q\n", r.URL.Path)
		}
	}
}

func handlerPackageBeats(sourceDir, storageDir, filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := zerolog.Ctx(r.Context())

		beatName := chi.URLParam(r, "beatName")
		sourceDir := filepath.Join(sourceDir, beatName)

		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			c = c.Str("beat", beatName)
			return c
		})

		files, err := packageBeats(ctx, sourceDir)
		if err != nil {
			logger.Error().Err(err).Msg("packing Beats")
			fmt.Fprintln(w, err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		for _, fullPath := range files {
			dstName := filepath.Join(storageDir, filename)
			if strings.HasSuffix(fullPath, ".sha512") {
				dstName += ".sha512"
			}

			// CREATE THE CHECK SUM MANUALLY!!!!

			if err := os.Rename(fullPath, dstName); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}

			logger.Debug().Msgf("moving: %s -> %s", fullPath, dstName)
		}

		fullPath := path.Join("/files", filename)
		http.Redirect(w, r, fullPath, http.StatusTemporaryRedirect)
	}
}

func copyFiles(ctx context.Context, sourceDir, storageDir string) error {
	logger := zerolog.Ctx(ctx)

	distDir := filepath.Join(sourceDir, "build", "distributions")
	dirInfo, err := os.ReadDir(distDir)
	if err != nil {
		return err
	}

	for _, f := range dirInfo {
		if f.IsDir() {
			continue
		}

		src := filepath.Join(distDir, f.Name())
		dst := filepath.Join(storageDir, f.Name())
		if err := os.Rename(src, dst); err != nil {
			return err
		}
		logger.Debug().Msgf("moving: %s -> %s", src, dst)
	}

	return nil
}

// packageBeats generates the tar.gz and sha512sum of the package.
// It returns the full path of the generated files and an error, if any
func packageBeats(ctx context.Context, sourceDir string) ([]string, error) {
	logger := zerolog.Ctx(ctx)

	goos := runtime.GOOS
	goarch := runtime.GOARCH

	if v, ok := os.LookupEnv("OS"); ok {
		goos = v
	}

	if v, ok := os.LookupEnv("ARCH"); ok {
		goarch = v
	}

	envs := map[string]string{
		"DEV":       "1",
		"PACKAGES":  "tar.gz",
		"PLATFORMS": fmt.Sprintf("%s/%s", goos, goarch),
	}
	args := []string{
		"mage",
		"-v",
		"package",
	}

	out, err := runCmd(ctx, sourceDir, envs, args...)
	if err != nil {
		return []string{}, err
	}

	filename := ""
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "Creating output file at") {
			filename = strings.TrimPrefix(l, "Creating output file at")
			filename = strings.TrimSpace(filename)
			logger.Info().Msgf("generated file: %q", filename)
		}
	}

	if filename == "" {
		return []string{}, errors.New("could not get the generated filenames ")
	}

	packagePath := filepath.Join(sourceDir, filename)
	files := []string{
		packagePath,
		packagePath + ".sha512",
	}

	return files, nil
}

// runCmd runs a command and returns its combined output and an error, if any.
func runCmd(ctx context.Context, pwd string, env map[string]string, command ...string) (string, error) {
	logger := zerolog.Ctx(ctx)

	envList := append([]string{}, os.Environ()...)
	for k, v := range env {
		e := fmt.Sprintf("%s=%s", k, v)
		envList = append(envList, e)
		logger.Debug().Msgf("build env var: %s", e)
	}

	c := command[0]
	args := command[1:]

	cmd := exec.Command(c, args...)
	cmd.Dir = pwd
	cmd.Env = envList

	logger.Debug().Msgf("entering folder: %s", cmd.Dir)
	logger.Debug().Msgf("running: %s %s", c, strings.Join(args, " "))

	combOut, err := cmd.CombinedOutput()
	if err != nil {
		return string(combOut), err
	}

	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return string(combOut), fmt.Errorf("exit code: %d", code)
	}

	return string(combOut), nil
}

// fileServer conveniently sets up a http.fileServer handler to serve
// static files from a http.FileSystem.
func fileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

func requestID(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestID := r.Header.Get(middleware.RequestIDHeader)
		if requestID == "" {
			requestID = xid.New().String()
		}
		ctx = context.WithValue(ctx, middleware.RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

func requestFields(next http.Handler) http.Handler {
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
