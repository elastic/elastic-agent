package diagnostics

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func Test_readServiceAccountToken(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		serviceAccountTokenContent []byte
		expectedPayload            *TokenPayload
		expectedErr                bool
	}{
		{
			name:                       "should succeed",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzg0NjQ1Nzg4LCJpYXQiOjE3NTMxMDk3ODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiYWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50LWJqOHpjIiwidWlkIjoiZWFkNGYwMWYtMTUzMi00ZTM2LWI5N2MtMThiOTYwOWIyODhjIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhZ2VudC1wZXJub2RlLWVsYXN0aWMtYWdlbnQiLCJ1aWQiOiIxYzU3NTA3My1hMDI0LTRmMGItYTdlNi1kMzBmNDY1NmE2N2UifSwid2FybmFmdGVyIjoxNzUzMTEzMzk1fSwibmJmIjoxNzUzMTA5Nzg4LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50In0.ARUU__Ha5-O-w6xokpiuBiK0I4KZsGZQDrYUl0ngVieDMWX7huk2SgBc7a94rhmNkrexiX86LU11EMOHJY-1szsnoLULKHYRwZp0t6LW1AcPOK5ysX-_hOfPmYUE8BmX5lJOuPZTrHjiSaOhtXB2Q_tuDPL_uHPCrLRruXKIygWg-9fxK_d8mfLqFPt_oxfBJyt7ODW8PtWdChVfAv-b4m4aD1357CJPrjVqegqSqZplU7KrLDBgLtohefoEEohPYRRo8M_vZsfkqUzfg5UjN81teGE61zaApwhua3OHFQ01m2XQDoU4oQbx4WznRsoddPeADeVpsSU76VnWCPDisw`),
			expectedPayload: &TokenPayload{
				Namespace: "kube-system",
				Pod: PodInfoToken{
					Name: "agent-pernode-elastic-agent-bj8zc",
					UID:  "ead4f01f-1532-4e36-b97c-18b9609b288c",
				},
				ServiceAccount: ServiceAccountInfoToken{
					Name: "agent-pernode-elastic-agent",
					UID:  "1c575073-a024-4f0b-a7e6-d30f4656a67e",
				},
			},
			expectedErr: false,
		},
		{
			name:                       "should fail because of less jwt parts",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzg0NjQ1Nzg4LCJpYXQiOjE3NTMxMDk3ODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiYWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50LWJqOHpjIiwidWlkIjoiZWFkNGYwMWYtMTUzMi00ZTM2LWI5N2MtMThiOTYwOWIyODhjIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhZ2VudC1wZXJub2RlLWVsYXN0aWMtYWdlbnQiLCJ1aWQiOiIxYzU3NTA3My1hMDI0LTRmMGItYTdlNi1kMzBmNDY1NmE2N2UifSwid2FybmFmdGVyIjoxNzUzMTEzMzk1fSwibmJmIjoxNzUzMTA5Nzg4LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50In0`),
			expectedPayload:            nil,
			expectedErr:                true,
		},
		{
			name:                       "should fail because of missing token file",
			serviceAccountTokenContent: nil,
			expectedPayload:            nil,
			expectedErr:                true,
		},
		{
			name:                       "should fail because of invalid base64 payload",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.SGVsbG8gd29ybGQ!@.ARUU__Ha5-O-w6xokpiuBiK0I4KZsGZQDrYUl0ngVieDMWX7huk2SgBc7a94rhmNkrexiX86LU11EMOHJY-1szsnoLULKHYRwZp0t6LW1AcPOK5ysX-_hOfPmYUE8BmX5lJOuPZTrHjiSaOhtXB2Q_tuDPL_uHPCrLRruXKIygWg-9fxK_d8mfLqFPt_oxfBJyt7ODW8PtWdChVfAv-b4m4aD1357CJPrjVqegqSqZplU7KrLDBgLtohefoEEohPYRRo8M_vZsfkqUzfg5UjN81teGE61zaApwhua3OHFQ01m2XQDoU4oQbx4WznRsoddPeADeVpsSU76VnWCPDisw`),
			expectedPayload:            nil,
			expectedErr:                true,
		},
		{
			name:                       "should fail because of invalid json",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5xNzg0NjQ1Nzg4LCJpYXQiOjE3NTMxMDk3ODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHV.ARUU__Ha5-O-w6xokpiuBiK0I4KZsGZQDrYUl0ngVieDMWX7huk2SgBc7a94rhmNkrexiX86LU11EMOHJY-1szsnoLULKHYRwZp0t6LW1AcPOK5ysX-_hOfPmYUE8BmX5lJOuPZTrHjiSaOhtXB2Q_tuDPL_uHPCrLRruXKIygWg-9fxK_d8mfLqFPt_oxfBJyt7ODW8PtWdChVfAv-b4m4aD1357CJPrjVqegqSqZplU7KrLDBgLtohefoEEohPYRRo8M_vZsfkqUzfg5UjN81teGE61zaApwhua3OHFQ01m2XQDoU4oQbx4WznRsoddPeADeVpsSU76VnWCPDisw`),
			expectedPayload:            nil,
			expectedErr:                true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "testfile")

			if len(tc.serviceAccountTokenContent) > 0 {
				err := os.WriteFile(tmpFile, tc.serviceAccountTokenContent, 0600)
				require.NoError(t, err, "failed to write service account file ", tmpFile)
			}

			payload, err := readServiceAccountToken(tmpFile)
			if tc.expectedErr {
				require.Error(t, err, "expected error but got none")
				require.Nil(t, payload)
			} else {
				require.NoError(t, err, "expected no error but got one")
				require.Equal(t, tc.expectedPayload, payload)
			}
		})
	}

}
