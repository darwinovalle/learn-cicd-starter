package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErr     error
		wantErrText string
	}{
		{
			name:        "valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey:     "abc123",
			wantErr:     nil,
			wantErrText: "",
		},
		{
			name:        "no authorization header at all",
			headers:     http.Header{},
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
			wantErrText: "",
		},
		{
			name:        "authorization header is empty string",
			headers:     http.Header{"Authorization": []string{""}},
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
			wantErrText: "",
		},
		{
			name:        "wrong prefix (Bearer instead of ApiKey)",
			headers:     http.Header{"Authorization": []string{"Bearer abc123"}},
			wantKey:     "",
			wantErr:     nil,
			wantErrText: "malformed authorization header",
		},
		{
			name:        "single token with no space",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:     "",
			wantErr:     nil,
			wantErrText: "malformed authorization header",
		},
		{
			name:        "prefix is case-sensitive (apikey lowercase)",
			headers:     http.Header{"Authorization": []string{"apikey abc123"}},
			wantKey:     "",
			wantErr:     nil,
			wantErrText: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}

			// Compare the sentinel error when one is expected.
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("got err %v, want %v", err, tt.wantErr)
				}
				return
			}

			// Otherwise match by message text.
			if tt.wantErrText != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErrText)
				}
				if err.Error() != tt.wantErrText {
					t.Errorf("got err %q, want %q", err.Error(), tt.wantErrText)
				}
			} else if err != nil {
				t.Errorf("got unexpected err %v", err)
			}
		})
	}
}
