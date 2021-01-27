package jwt

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	jwtauth "github.com/greenpau/caddy-auth-jwt/pkg/auth"
	"github.com/satori/go.uuid"
)

func init() {
	caddy.RegisterModule(AuthMiddleware{})
}

type AuthMiddleware struct {
	Authorizer *jwtauth.Authorizer `json:"authorizer,omitempty"`
}

func (AuthMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(AuthMiddleware) },
	}
}

func (m *AuthMiddleware) Provision(ctx caddy.Context) error {
	opts := make(map[string]interface{})
	opts["logger"] = ctx.Logger(m)
	return m.Authorizer.Provision(opts)
}

func (m *AuthMiddleware) Validate() error {
	return nil
}

func (m AuthMiddleware) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	reqID := GetRequestID(r)
	opts := make(map[string]interface{})
	opts["request_id"] = reqID
	user, authOK, err := m.Authorizer.Authenticate(w, r, opts)
	if user == nil {
		return caddyauth.User{}, authOK, err
	}
	userIdentity := caddyauth.User{
		Metadata: map[string]string{
			"roles": user["roles"].(string),
			"email": user["email"].(string),
		},
	}
	if v, exists := user["id"]; exists {
		userIdentity.ID = v.(string)
	}
	for _, k := range []string{"claim_id", "sub", "email", "name"} {
		if v, exists := user[k]; exists {
			userIdentity.Metadata[k] = v.(string)
		}
	}
	fmt.Println("----------------------------")
	fmt.Printf("%v\n", userIdentity)
	fmt.Println("----------------------------")
	return userIdentity, authOK, err
}

var (
	_ caddy.Provisioner       = (*AuthMiddleware)(nil)
	_ caddy.Validator         = (*AuthMiddleware)(nil)
	_ caddyauth.Authenticator = (*AuthMiddleware)(nil)
)

func GetRequestID(r *http.Request) string {
	rawRequestID := caddyhttp.GetVar(r.Context(), "request_id")
	if rawRequestID == nil {
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = uuid.NewV4().String()
		}
		caddyhttp.SetVar(r.Context(), "request_id", requestID)
		return requestID
	}
	return rawRequestID.(string)
}
