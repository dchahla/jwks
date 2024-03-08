package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type FirebaseToken struct {
	Audience string `json:"aud"`
	// Add other fields from FirebaseToken struct if needed
}

type JWKSKey struct {
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
}

type JWKS struct {
	Keys []*JWKSKey `json:"keys"`
}

type KeySet struct {
	Keys []*JWKSKey
	mu   sync.RWMutex
}

type MiddlewareFunc func(http.Handler) http.Handler

var (
	jwksURL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
)

func fetchJWKS() (*JWKS, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
}

func publicKeyFromJWK(key *JWKSKey) (*rsa.PublicKey, error) {
	modulus, err := decodeBase64URL(key.N)
	if err != nil {
		return nil, err
	}

	exponent, err := decodeBase64URL(key.E)
	if err != nil {
		return nil, err
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponent).Int64()),
	}

	return pubKey, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)

	m := len(s) % 4
	if m != 0 {
		s += strings.Repeat("=", 4-m)
	}

	return base64.StdEncoding.DecodeString(s)
}

func NewKeySet() (*KeySet, error) {
	ks := &KeySet{}
	if err := ks.update(); err != nil {
		return nil, err
	}

	go func() {
		for range time.Tick(time.Hour) {
			_ = ks.update()
		}
	}()

	return ks, nil
}

func (ks *KeySet) update() error {
	jwks, err := fetchJWKS()
	if err != nil {
		return err
	}

	keys := make([]*JWKSKey, len(jwks.Keys))
	for i, key := range jwks.Keys {
		keys[i] = key
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Kid < keys[j].Kid
	})

	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.Keys = keys

	return nil
}

func (ks *KeySet) PublicKey(kid string) (*rsa.PublicKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	for _, key := range ks.Keys {
		if key.Kid == kid {
			return publicKeyFromJWK(key)
		}
	}

	return nil, fmt.Errorf("public key not found for kid %s", kid)
}

func Verify(audience string, algorithm string, keys *KeySet) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := extractToken(r)
			if tokenString == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			claims, err := verifyToken(tokenString, audience, algorithm, keys)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "claims", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func verifyToken(tok string, audience, algorithm string, keys *KeySet) (jwt.Claims, error) {
	token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		pubKey, err := keys.PublicKey(kid)
		if err != nil {
			return nil, err
		}

		switch {
		case strings.HasPrefix(algorithm, "ES"):
			return pubKey, nil
		case strings.HasPrefix(algorithm, "RS") || strings.HasPrefix(algorithm, "PS"):
			return pubKey, nil
		default:
			return nil, fmt.Errorf("unsupported algorithm")
		}
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	aud, ok := claims["aud"].(string)
	if !ok || aud != audience {
		return nil, fmt.Errorf("invalid audience")
	}

	return claims, nil
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}
