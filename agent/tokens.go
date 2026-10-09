package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Claims carried by user tokens and delegation tokens.
type Claims struct {
	jwt.Claims
	Scope string `json:"scope,omitempty"`
	// Act is the RFC 8693 actor claim: the agent acting on behalf of Subject.
	Act *Actor `json:"act,omitempty"`
}

type Actor struct {
	Sub string `json:"sub"`
}

// issuer signs tokens with a key generated at startup. The public key is
// published as a JWKS; the private key never leaves the process.
type issuer struct {
	iss    string
	kid    string
	key    *ecdsa.PrivateKey
	signer jose.Signer
}

func newIssuer(iss string) (*issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := fmt.Sprintf("key-%d", time.Now().Unix())
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		return nil, err
	}
	return &issuer{iss: iss, kid: kid, key: key, signer: signer}, nil
}

func (i *issuer) issue(sub, aud string, ttl time.Duration, scope string, act *Actor) (string, error) {
	now := time.Now()
	return jwt.Signed(i.signer).Claims(Claims{
		Claims: jwt.Claims{
			Issuer:   i.iss,
			Subject:  sub,
			Audience: jwt.Audience{aud},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(ttl)),
		},
		Scope: scope,
		Act:   act,
	}).Serialize()
}

func (i *issuer) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &i.key.PublicKey, KeyID: i.kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
}

func (i *issuer) verify(raw, aud string) (*Claims, error) {
	return verifyToken(raw, i.iss, aud, func(kid string) (any, error) {
		if kid != i.kid {
			return nil, fmt.Errorf("unknown signing key %q", kid)
		}
		return &i.key.PublicKey, nil
	})
}

// remoteVerifier checks tokens against the token service's JWKS, fetched
// over mTLS so the keys provably come from the token service.
type remoteVerifier struct {
	client  *http.Client
	jwksURL string
	iss     string

	mu   sync.Mutex
	keys jose.JSONWebKeySet
}

func newRemoteVerifier(source *workloadapi.X509Source, url string, id spiffeid.ID) *remoteVerifier {
	return &remoteVerifier{client: mtlsClient(source, id), jwksURL: url + "/jwks", iss: id.String()}
}

func (v *remoteVerifier) verify(raw, aud string) (*Claims, error) {
	return verifyToken(raw, v.iss, aud, v.key)
}

// key returns the public key for kid, refreshing the JWKS once if unknown
// (e.g. after the token service restarts with a new key).
func (v *remoteVerifier) key(kid string) (any, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ks := v.keys.Key(kid); len(ks) > 0 {
		return ks[0].Key, nil
	}
	resp, err := v.client.Get(v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&v.keys); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}
	if ks := v.keys.Key(kid); len(ks) > 0 {
		return ks[0].Key, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

// verifyToken checks the signature, issuer, audience and expiry of raw.
func verifyToken(raw, iss, aud string, keyFor func(kid string) (any, error)) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	key, err := keyFor(tok.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := tok.Claims(key, &c); err != nil {
		return nil, fmt.Errorf("bad signature: %w", err)
	}
	if err := c.Claims.Validate(jwt.Expected{Issuer: iss, AnyAudience: jwt.Audience{aud}, Time: time.Now()}); err != nil {
		return nil, err
	}
	return &c, nil
}
