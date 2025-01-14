package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/stretchr/testify/require"
)

func TestOtelConfigVerification(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
	})

	t.Run("file-provider", func(t *testing.T) {
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		out, err := fixture.Exec(context.Background(), []string{"otel", "validate", "--config=./test-otel-config.yml"})
		require.NoError(t, err, string(out))
	})

	t.Run("env-provider", func(t *testing.T) {
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		envVarName := "TEST_OTEL_CONFIG"
		testConf, err := os.ReadFile("./test-otel-config.yml")
		require.NoError(t, err)

		err = os.Setenv(envVarName, string(testConf))
		require.NoError(t, err)
		defer func() {
			err := os.Unsetenv(envVarName)
			require.NoError(t, err)
		}()

		out, err := fixture.Exec(context.Background(), []string{"otel", "validate", fmt.Sprintf("--config=env:%s", envVarName)})
		require.NoError(t, err, string(out))
	})

	t.Run("yaml-provider", func(t *testing.T) {
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		out, err := fixture.Exec(context.Background(), []string{"otel", "validate", "--config=./test-otel-config.yml", "--config=yaml:testing::test::t: 1"})
		require.NoError(t, err, out)
	})

	t.Run("http-provider", func(t *testing.T) {
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		testConf, err := os.ReadFile("./test-otel-config.yml")
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(testConf)
		}))
		defer server.Close()

		out, err := fixture.Exec(context.Background(), []string{"otel", "validate", fmt.Sprintf("--config=%s", server.URL)})
		require.NoError(t, err, string(out))
	})
}
