package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "valid API key",
			headers: http.Header{"Authorization": []string{"ApiKey secret-key"}},
			wantKey: "secret-key",
		},
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "missing API key",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "incorrect authorization scheme",
			headers:    http.Header{"Authorization": []string{"Bearer secret-key"}},
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErrMsg != "" && (err == nil || err.Error() != tt.wantErrMsg) {
				t.Fatalf("GetAPIKey() error = %v, want %q", err, tt.wantErrMsg)
			}
			if tt.wantErr == nil && tt.wantErrMsg == "" && err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
