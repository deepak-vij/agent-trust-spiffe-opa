// A minimal "AI agent" that talks to other agents over mTLS, using
// SPIFFE X.509 SVIDs fetched from the SPIRE Workload API. No certificates,
// keys, or secrets are baked into the image or passed via config.
//
// Authentication (who is calling?) is done by mTLS with SPIFFE IDs.
// Delegation (on whose behalf?) is carried by a short-lived token from the
// token service. Authorization (may they do this?) is delegated to OPA.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type Task struct {
	From  string `json:"from"`
	Query string `json:"query"`
}

type Result struct {
	Agent        string `json:"agent"`
	CallerVerify string `json:"caller_verified_as"`
	OnBehalfOf   string `json:"on_behalf_of"`
	Tool         string `json:"tool"`
	Answer       string `json:"answer"`
}

// Decision is what OPA returns for a policy's "decision" rule.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

func main() {
	mode := os.Getenv("MODE") // "server", "client" or "token-service"
	socket := envOr("SPIFFE_ENDPOINT_SOCKET", "unix:///opt/spire/sockets/agent.sock")

	ctx := context.Background()
	log.Printf("[%s] fetching SVID from Workload API at %s ...", mode, socket)
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		log.Fatalf("unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("unable to get SVID: %v", err)
	}
	log.Printf("my identity: %s (expires %s)", svid.ID, svid.Certificates[0].NotAfter.Format(time.RFC3339))

	switch mode {
	case "server":
		runServer(source, svid.ID)
	case "client":
		runClient(source)
	case "token-service":
		runTokenService(source, svid.ID)
	default:
		log.Fatalf("MODE must be server, client or token-service")
	}
}

// runServer exposes tools at POST /tools/{tool}. mTLS accepts any agent from
// our trust domain; the caller must present a delegation token naming the
// user it acts for, and OPA decides per request whether the call is allowed.
func runServer(source *workloadapi.X509Source, self spiffeid.ID) {
	opaURL := os.Getenv("OPA_URL")
	log.Printf("authorization delegated to OPA at %s", opaURL)
	opa := &http.Client{Timeout: 2 * time.Second}
	tokens := newRemoteVerifier(source, os.Getenv("TOKEN_SERVICE_URL"), spiffeid.RequireFromString(os.Getenv("TOKEN_SERVICE_ID")))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /tools/{tool}", func(w http.ResponseWriter, r *http.Request) {
		caller, err := peerID(r)
		if err != nil {
			http.Error(w, "no SPIFFE ID", http.StatusUnauthorized)
			return
		}
		tool := r.PathValue("tool")

		// The delegation token is optional at this layer; policy decides
		// whether a call without one is acceptable.
		user, actor, scope := "", "", ""
		if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			c, err := tokens.verify(raw, self.String())
			if err != nil {
				log.Printf("REJECT %s -> %s: invalid delegation token: %v", caller, tool, err)
				http.Error(w, "invalid delegation token: "+err.Error(), http.StatusUnauthorized)
				return
			}
			user, scope = c.Subject, c.Scope
			if c.Act != nil {
				actor = c.Act.Sub
			}
		}

		d, err := queryOPA(opa, opaURL+"/v1/data/agents/authz/decision", map[string]string{
			"caller": caller.String(),
			"target": self.String(),
			"tool":   tool,
			"user":   user,
			"actor":  actor,
			"scope":  scope,
		})
		if err != nil { // fail closed if the policy engine is unreachable
			log.Printf("OPA error, denying %s -> %s: %v", caller, tool, err)
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
			return
		}
		if !d.Allow {
			log.Printf("DENY  %s for %q -> %s (%s)", caller, user, tool, d.Reason)
			http.Error(w, d.Reason, http.StatusForbidden)
			return
		}

		var t Task
		_ = json.NewDecoder(r.Body).Decode(&t)
		log.Printf("ALLOW %s for %q -> %s %q", caller, user, tool, t.Query)
		json.NewEncoder(w).Encode(Result{
			Agent:        self.String(),
			CallerVerify: caller.String(),
			OnBehalfOf:   user,
			Tool:         tool,
			Answer:       fmt.Sprintf("%s result for %q", tool, t.Query),
		})
	})

	serveMTLS(source, self, mux)
}

// serveMTLS serves mux on :8443, accepting any client from our trust domain.
func serveMTLS(source *workloadapi.X509Source, self spiffeid.ID, mux *http.ServeMux) {
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(self.TrustDomain())),
		ErrorLog:  log.New(os.Stderr, "[tls] ", log.LstdFlags),
	}
	log.Printf("listening on :8443 (mTLS)")
	log.Fatal(srv.ListenAndServeTLS("", "")) // certs come from TLSConfig
}

// mtlsClient returns an HTTP client that only talks to a server proving id.
func mtlsClient(source *workloadapi.X509Source, id spiffeid.ID) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id)),
		},
	}
}

// peerID returns the SPIFFE ID of the mTLS-authenticated caller.
func peerID(r *http.Request) (spiffeid.ID, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return spiffeid.ID{}, fmt.Errorf("no client certificate")
	}
	return x509svid.IDFromCert(r.TLS.PeerCertificates[0])
}

// queryOPA asks OPA for the decision at url.
func queryOPA(c *http.Client, url string, input map[string]string) (Decision, error) {
	body, _ := json.Marshal(map[string]any{"input": input})
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Result *Decision `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Decision{}, err
	}
	if out.Result == nil {
		return Decision{}, fmt.Errorf("policy returned no decision")
	}
	return *out.Result, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
