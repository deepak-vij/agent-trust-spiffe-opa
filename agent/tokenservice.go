package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"
	delegationTTL      = 5 * time.Minute
)

// runTokenService issues delegation tokens. It plays two roles:
//   - POST /login: a stand-in for the user's identity provider (Okta, Entra
//     ID, ...), issuing an ID token for a demo user.
//   - POST /token: RFC 8693 token exchange. An agent, authenticated by its
//     SPIFFE ID over mTLS, trades a user's ID token for a short-lived token
//     that lets it act for that user, on one target, for one tool.
func runTokenService(source *workloadapi.X509Source, self spiffeid.ID) {
	iss, err := newIssuer(self.String())
	if err != nil {
		log.Fatalf("unable to create signing key: %v", err)
	}
	opaURL := os.Getenv("OPA_URL")
	opa := &http.Client{Timeout: 2 * time.Second}
	users := strings.Split(envOr("DEMO_USERS", "maria,alex"), ",")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(iss.jwks())
	})

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		if !slices.Contains(users, user) {
			oauthError(w, http.StatusUnauthorized, "access_denied", "unknown user "+user)
			return
		}
		tok, _ := iss.issue(user, self.String(), time.Hour, "", nil)
		w.Write([]byte(tok))
	})

	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		actor, err := peerID(r)
		if err != nil {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "no SPIFFE ID")
			return
		}
		if r.FormValue("grant_type") != grantTokenExchange {
			oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only token exchange is supported")
			return
		}
		user, err := iss.verify(r.FormValue("subject_token"), self.String())
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid subject_token: "+err.Error())
			return
		}
		audience, scope := r.FormValue("audience"), r.FormValue("scope")

		d, err := queryOPA(opa, opaURL+"/v1/data/agents/delegation/decision", map[string]string{
			"actor":    actor.String(),
			"user":     user.Subject,
			"audience": audience,
			"scope":    scope,
		})
		if err != nil { // fail closed
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authorization unavailable")
			return
		}
		if !d.Allow {
			log.Printf("REFUSE %s for %q -> %s %s (%s)", actor, user.Subject, audience, scope, d.Reason)
			oauthError(w, http.StatusForbidden, "access_denied", d.Reason)
			return
		}

		// The actor claim is the mTLS-verified caller, never a request
		// parameter, so an agent cannot obtain a token in another's name.
		tok, err := iss.issue(user.Subject, audience, delegationTTL, scope, &Actor{Sub: actor.String()})
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		log.Printf("ISSUE  %s for %q -> %s %s (%s)", actor, user.Subject, audience, scope, delegationTTL)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      tok,
			"issued_token_type": tokenTypeJWT,
			"token_type":        "Bearer",
			"expires_in":        int(delegationTTL.Seconds()),
		})
	})

	serveMTLS(source, self, mux)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
