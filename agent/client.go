package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// A scripted call: act for user (none if empty) and invoke tool. forged
// edits the delegation token to claim a different user, to show tampering
// is caught.
type call struct {
	user   string
	tool   string
	forged bool
}

// parseCalls reads CALLS, e.g. "maria:research,:research,maria~forged:summarize".
func parseCalls(s string) []call {
	var calls []call
	for _, item := range strings.Split(s, ",") {
		user, tool, _ := strings.Cut(strings.TrimSpace(item), ":")
		user, forged := strings.CutSuffix(user, "~forged")
		calls = append(calls, call{user: user, tool: tool, forged: forged})
	}
	return calls
}

func (c call) String() string {
	switch {
	case c.user == "":
		return "no user"
	case c.forged:
		return fmt.Sprintf("for %s, token edited to say alex", c.user)
	default:
		return "for " + c.user
	}
}

// runClient cycles through CALLS against TARGET_URL, verifying that the
// server presents TARGET_ID. For each user it first obtains a delegation
// token from the token service.
func runClient(source *workloadapi.X509Source) {
	target := os.Getenv("TARGET_URL")
	serverID := spiffeid.RequireFromString(os.Getenv("TARGET_ID"))
	tsURL := os.Getenv("TOKEN_SERVICE_URL")
	tsClient := mtlsClient(source, spiffeid.RequireFromString(os.Getenv("TOKEN_SERVICE_ID")))
	client := mtlsClient(source, serverID)
	calls := parseCalls(envOr("CALLS", "maria:research"))

	for i := 0; ; i++ {
		c := calls[i%len(calls)]
		time.Sleep(3 * time.Second)

		req, _ := http.NewRequest("POST", target+"/tools/"+c.tool, bytes.NewReader(
			fmt.Appendf(nil, `{"query":"topic #%d"}`, i+1)))
		req.Header.Set("Content-Type", "application/json")
		if c.user != "" {
			tok, err := delegate(tsClient, tsURL, c.user, serverID.String(), c.tool)
			if err != nil {
				log.Printf("REFUSED  %-14s %-36s token service: %v", c.tool, c, err)
				continue
			}
			if c.forged {
				tok = forge(tok, "alex")
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("REJECTED %-14s %-36s %v", c.tool, c, err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		verdict := "OK      "
		if resp.StatusCode != http.StatusOK {
			verdict = "DENIED  "
		}
		log.Printf("%s %-14s %-36s -> %s %s", verdict, c.tool, c, resp.Status, strings.TrimSpace(string(b)))
	}
}

// delegate obtains a token letting this agent act for user on audience,
// for one tool.
func delegate(c *http.Client, tsURL, user, audience, tool string) (string, error) {
	// 1. The user signs in. In production this happens at the user's identity
	//    provider, and the application hands the resulting token to the agent.
	resp, err := c.PostForm(tsURL+"/login", url.Values{"user": {user}})
	if err != nil {
		return "", err
	}
	idToken, err := readToken(resp, func(b []byte) (string, error) { return string(b), nil })
	if err != nil {
		return "", err
	}

	// 2. RFC 8693 token exchange: trade the user's token for a delegation token.
	resp, err = c.PostForm(tsURL+"/token", url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {idToken},
		"subject_token_type": {tokenTypeJWT},
		"audience":           {audience},
		"scope":              {tool},
	})
	if err != nil {
		return "", err
	}
	return readToken(resp, func(b []byte) (string, error) {
		var out struct {
			AccessToken string `json:"access_token"`
		}
		err := json.Unmarshal(b, &out)
		return out.AccessToken, err
	})
}

// readToken returns the token parsed from a successful response, or the
// OAuth error description from a failed one.
func readToken(resp *http.Response, parse func([]byte) (string, error)) (string, error) {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Desc string `json:"error_description"`
		}
		if json.Unmarshal(b, &e) == nil && e.Desc != "" {
			return "", errors.New(e.Desc)
		}
		return "", fmt.Errorf("%s", resp.Status)
	}
	return parse(b)
}

// forge rewrites the token's subject without re-signing it, the way an
// attacker might try to escalate from one user to another.
func forge(tok, sub string) string {
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	claims["sub"] = sub
	payload, _ = json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}
