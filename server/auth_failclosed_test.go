package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// GetSetting tells "key not set" and "read failed" apart only by its error: the
// value is "" in both cases. A password handler that reads the error as "no
// password yet" opens the first-run path while the DB is flaky — authInit would
// let a request overwrite the existing admin password, and authStatus would send
// the web UI to /setup to do exactly that. (Upstream ARTEX v0.3.15, PR #197.)
//
// These tests close the handler's pool to force read failures and assert every
// password path fails closed.

// newClosedPGServer returns a Server whose DB handle is already closed, so every
// query errors instead of returning sql.ErrNoRows.
func newClosedPGServer(t *testing.T) *Server {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(setupTokenEnv, "known-setup-token-for-this-test-0001")
	t.Setenv(adminPasswordEnv, "")
	return &Server{m: &Manager{pg: d}, jwtKey: []byte(strings.Repeat("s", 32))}
}

func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	s := newClosedPGServer(t)
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 (a failed read reported as uninitialised sends the user to /setup); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("a failed read must not answer initialized, got %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	s := newClosedPGServer(t)
	w := httptest.NewRecorder()
	// Even with the correct setup token, an unreadable password state must not
	// reach the write.
	body := strings.NewReader(`{"password":"correct horse battery","setup_token":"known-setup-token-for-this-test-0001"}`)
	s.authInit(w, httptest.NewRequest(http.MethodPost, "/api/auth/init", body))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 (letting the request through could overwrite an existing password); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("a failed read must not issue a token: %s", w.Body.String())
	}
}

func TestAuthLoginFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	s := newClosedPGServer(t)
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"username":"ARTEX","password":"whatever-123"}`)
	s.authLogin(w, httptest.NewRequest(http.MethodPost, "/api/auth/login", body))

	// 403 "not initialised" would also send the UI toward /setup.
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", w.Code, w.Body.String())
	}
}

func TestVerifyTokenFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	s := newClosedPGServer(t)
	// A token signed with the raw key would verify against signingKey("") if a
	// failed read were folded into "no password".
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if s.verifyToken(tok) {
		t.Fatal("verifyToken must reject every token while the password state is unreadable")
	}
}

func TestBootstrapAuthSkipsFirstRunWhenDataSourceUnavailable(t *testing.T) {
	s := newClosedPGServer(t)
	s.bootstrapAuth()
	s.authMu.Lock()
	loaded := s.passHashLoaded
	s.authMu.Unlock()
	if loaded {
		t.Fatal("a failed read must not be cached as \"no password\"")
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		want     string
	}{
		{"empty", "", authErrPasswordTooShort},
		{"7 chars", "1234567", authErrPasswordTooShort},
		{"8 chars", "12345678", ""},
		{"8 Hangul runes count as characters, not bytes", "비밀번호비밀번호", ""},
		{"3 Hangul runes are 9 bytes but only 3 characters", "비밀번", authErrPasswordTooShort},
		{"72 bytes", strings.Repeat("a", 72), ""},
		{"73 bytes exceeds the bcrypt limit", strings.Repeat("a", 73), authErrPasswordTooLong},
		{"25 Hangul runes are 75 bytes", strings.Repeat("가", 25), authErrPasswordTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); got != tc.want {
				t.Fatalf("validatePassword(%q)=%q, want %q", tc.pw, got, tc.want)
			}
		})
	}
}

func TestAuthInitRejectsPasswordOverBcryptLimitDB(t *testing.T) {
	rig := newAuthTestRig(t)
	rig.s.bootstrapAuth()
	setup := rig.s.currentSetupToken()
	code, body := rig.do(http.MethodPost, "/api/auth/init", "", map[string]any{"password": strings.Repeat("a", 73), "setup_token": setup})
	rig.expect(400, code, body, authErrPasswordTooLong)
	if h, _ := rig.s.reloadPassHash(); h != "" {
		t.Fatal("a rejected init must not store a password")
	}
}
