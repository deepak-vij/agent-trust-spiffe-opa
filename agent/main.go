// A minimal "AI agent" that talks to other agents over mTLS, using
// SPIFFE X.509 SVIDs fetched from the SPIRE Workload API. No certificates,
// keys, or secrets are baked into the image or passed via config.
//
// Authentication (who is calling?) is done by mTLS with SPIFFE IDs.
// Authorization (may they do this?) is delegated to OPA on every request.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	Tool         string `json:"tool"`
	Answer       string `json:"answer"`
}

// Decision is what OPA returns for data.agents.authz.decision.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

func main() {
	mode := os.Getenv("MODE") // "server" or "client"
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
	default:
		log.Fatalf("MODE must be server or client")
	}
}

// runServer exposes tools at POST /tools/{tool}. mTLS accepts any agent from
// our trust domain; OPA then decides per request whether the call is allowed.
func runServer(source *workloadapi.X509Source, self spiffeid.ID) {
	opaURL := os.Getenv("OPA_URL")
	log.Printf("authorization delegated to OPA at %s", opaURL)
	opa := &http.Client{Timeout: 2 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /tools/{tool}", func(w http.ResponseWriter, r *http.Request) {
		caller, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
		if err != nil {
			http.Error(w, "no SPIFFE ID", http.StatusUnauthorized)
			return
		}
		tool := r.PathValue("tool")

		d, err := authorize(opa, opaURL, map[string]string{
			"caller": caller.String(),
			"target": self.String(),
			"tool":   tool,
		})
		if err != nil { // fail closed if the policy engine is unreachable
			log.Printf("OPA error, denying %s -> %s: %v", caller, tool, err)
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
			return
		}
		if !d.Allow {
			log.Printf("DENY  %s -> %s (%s)", caller, tool, d.Reason)
			http.Error(w, d.Reason, http.StatusForbidden)
			return
		}

		var t Task
		_ = json.NewDecoder(r.Body).Decode(&t)
		log.Printf("ALLOW %s -> %s %q", caller, tool, t.Query)
		json.NewEncoder(w).Encode(Result{
			Agent:        self.String(),
			CallerVerify: caller.String(),
			Tool:         tool,
			Answer:       fmt.Sprintf("%s result for %q", tool, t.Query),
		})
	})

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(self.TrustDomain())),
		ErrorLog:  log.New(os.Stderr, "[tls] ", log.LstdFlags),
	}
	log.Printf("listening on :8443 (mTLS)")
	log.Fatal(srv.ListenAndServeTLS("", "")) // certs come from TLSConfig
}

// authorize asks OPA for data.agents.authz.decision.
func authorize(c *http.Client, opaURL string, input map[string]string) (Decision, error) {
	body, _ := json.Marshal(map[string]any{"input": input})
	resp, err := c.Post(opaURL+"/v1/data/agents/authz/decision", "application/json", bytes.NewReader(body))
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

// runClient cycles through TOOLS, calling each on TARGET_URL and verifying
// that the server presents TARGET_ID.
func runClient(source *workloadapi.X509Source) {
	target := os.Getenv("TARGET_URL")
	serverID := spiffeid.RequireFromString(os.Getenv("TARGET_ID"))
	tools := strings.Split(envOr("TOOLS", "research"), ",")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID)),
		},
	}

	for i := 0; ; i++ {
		tool := strings.TrimSpace(tools[i%len(tools)])
		svid, _ := source.GetX509SVID()
		body, _ := json.Marshal(Task{From: svid.ID.String(), Query: fmt.Sprintf("topic #%d", i+1)})
		resp, err := client.Post(target+"/tools/"+tool, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("REJECTED %s on %s: %v", tool, serverID, err)
		} else {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			verdict := "OK    "
			if resp.StatusCode != http.StatusOK {
				verdict = "DENIED"
			}
			log.Printf("%s %s -> %s %s", verdict, tool, resp.Status, strings.TrimSpace(string(b)))
		}
		time.Sleep(3 * time.Second)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
