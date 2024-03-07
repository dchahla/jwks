package jwks

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)
type FirebaseToken struct {
    Audience     string `json:"aud"`
    AuthTime     int64  `json:"auth_time"`
    Expiry       int64  `json:"exp"`
    Firebase     struct {
        Identities      map[string]interface{} `json:"identities"`
        SignInProvider  string                 `json:"sign_in_provider"`
    } `json:"firebase"`
    IssuedAt     int64  `json:"iat"`
    Issuer       string `json:"iss"`
    ProviderID   string `json:"provider_id"`
    Subject      string `json:"sub"`
    UserID       string `json:"user_id"`
}
type KeySet struct {
    Primary    []byte
    Fallbacks  [][]byte
}
type MiddlewareFunc func(http.Handler) http.Handler

func StartKeySetUpdateRoutine(keys *KeySet) {
    // Define a function to update the key set
    updateFunc := func() {
        newKeys := InitKeySet()
        if err := updateKeysIfNewPrimary(newKeys.Primary, keys); err != nil {
            // Handle error
            // For example, log the error
            log.Println("Failed to update keys:", err)
        }
    }

    // Run the update function once after an initial delay of an hour
    time.AfterFunc(time.Hour, updateFunc)

    // Set up ticker to run the update function every hour
    ticker := time.NewTicker(time.Hour)
    defer ticker.Stop()

    // Run the update function at every tick
    for {
        select {
        case <-ticker.C:
            updateFunc()
        }
    }
}
func InitKeySet() KeySet {
	// Define a struct to represent the JSON data
	type Key struct {
		E   string `json:"e"`
		N   string `json:"n"`
		Alg string `json:"alg"`
	}

	type KeyContainer struct {
		Keys []Key `json:"keys"`
	}
	url := "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
	response, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching URL: %v", err)
	}
	defer response.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v", err)
	}

	// Print the contents of the webpage
	// fmt.Println(string(body))
	// Unmarshal JSON data into the defined struct
	var keyContainer KeyContainer
	if err := json.Unmarshal([]byte(string(body)), &keyContainer); err != nil {
		log.Fatal(err)
	}
	// count := 0

	// Initialize KeySet
	var keySet KeySet

	// Iterate over each key and construct public key
	for _, key := range keyContainer.Keys {
		// if count < 2 { // Check if it's the second iteration (index 1)
			// Decode base64url encoded strings
			modulus, err := decodeBase64URL(key.N)
			if err != nil {
				log.Fatal(err)
			}

			exponent, err := decodeBase64URL(key.E)
			if err != nil {
				log.Fatal(err)
			}

			// Construct big.Int from modulus and exponent
			modulusInt := new(big.Int)
			modulusInt.SetBytes(modulus)

			exponentInt := new(big.Int)
			exponentInt.SetBytes(exponent)

			// Construct rsa.PublicKey
			publicKey := &rsa.PublicKey{
				N: modulusInt,
				E: int(exponentInt.Int64()),
			}

			// Convert public key to PEM format
			publicKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(publicKey),
			})
			// Print public key information
			fmt.Printf("Public Key:\n%s\n", publicKeyPEM)

			// Define fallback public keys
			fallbackPublicKeys := [][]byte{
				// Add more fallback keys as needed
			}
			keySet.Primary = publicKeyPEM
			keySet.Fallbacks = fallbackPublicKeys
			err = updateKeysIfNewPrimary(publicKeyPEM, &keySet)
			if err != nil {
				fmt.Println("Failed to update keys:", err)
			}

			// return keySet
		// }
		// count++
	}

	return keySet
}
func Verify(audience string, algorithm string, keys *KeySet) MiddlewareFunc {


	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the JWT token from the request headers
			tokenString := extractToken(r)
			if tokenString == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Verify the token
			err := verifyTokenWithFallback(tokenString, keys, algorithm)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
				// Split the token into its three parts: header, payload, and signature
			parts := strings.Split(tokenString, ".")
			if len(parts) != 3 {
				fmt.Println("Invalid token format")
				return
			}
			// Decode and parse the payload (claims)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				fmt.Println("Error decoding payload:", err)
				return
			}

			// Token is valid, call the next handler
			// fmt.Println(string(payload))
			var userToken FirebaseToken
			if err := json.Unmarshal(payload, &userToken); err != nil {
				log.Fatal(err)
			}
			if userToken.Audience == audience && userToken.Issuer == "https://securetoken.google.com/"+audience {
				ctx := r.Context() 
				ctx = context.WithValue(ctx, "claims", string(payload))
				next.ServeHTTP(w, r.WithContext(ctx))
				// r.Header.Set("User", string(payload))
				// next.ServeHTTP(w, r)
			} else {
				fmt.Println("Expected JWT audience to be : https://securetoken.google.com/"+audience)

				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			

			// next.ServeHTTP(w, r)
		})
	}
}

// extractToken extracts the token from the request headers.
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}

// Check if a new public key is available and update the keys accordingly
func updateKeysIfNewPrimary(publicKeyPEM []byte, keys *KeySet) error {
    // Parse the new public key from PEM format
    block, _ := pem.Decode(publicKeyPEM)
    if block == nil || block.Type != "PUBLIC KEY" {
        fmt.Println("failed to decode public key PEM")
    }

    newPublicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse new public key: %w", err)
    }

    // Marshal the new public key to byte slice
    newKeyBytes := x509.MarshalPKCS1PublicKey(newPublicKey)

    // Compare the byte representations of the new public key with the current primary key
    if !bytes.Equal(newKeyBytes, keys.Primary) {
        // Update keys if the new public key is different from the current primary key
        keys.Fallbacks = append(keys.Fallbacks, keys.Primary)
        keys.Primary = newKeyBytes

        // Cap the number of fallback keys at two
        if len(keys.Fallbacks) > 3 {
            keys.Fallbacks = keys.Fallbacks[len(keys.Fallbacks)-3:]
        }
    }
	// fmt.Println( keys.Primary, keys.Fallbacks)
    return nil
}


// Function to decode base64url encoded string
func decodeBase64URL(s string) ([]byte, error) {
	// Convert from base64url to base64
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	// Add padding if necessary
	m := len(s) % 4
	if m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	// Decode base64
	return base64.StdEncoding.DecodeString(s)
}
func verifyTokenWithFallback(tok string, keys *KeySet, algorithm string) error {
    // Attempt verification with the primary key
    claims, err := verifyToken(tok, keys.Primary, algorithm)
    if err == nil {
        return nil // Token verified successfully with primary key
    }
	// fmt.Println(claims)
    // If verification fails with the primary key and it did not return claims, try fallback keys
    if claims == nil {
        // Iterate through the last two fallback keys
        for i := len(keys.Fallbacks) - 1; i >= 0 && i >= len(keys.Fallbacks)-2; i-- {
            key := keys.Fallbacks[i]
            claims, err = verifyToken(tok, key, algorithm)
            if err == nil {
                return nil // Token verified successfully with fallback key
            }
        }
    }

    // All attempts failed, return an error
    return fmt.Errorf("failed to verify token with all keys")
}


func verifyToken(tokData string, publicKey []byte, alg string) (jwt.Claims, error) {
    // Trim whitespace from token
    tokData = strings.TrimSpace(tokData)
    // Parse the token. Load the key from wherever it's set in your program
    token, err := jwt.Parse(string(tokData), func(t *jwt.Token) (interface{}, error) {
        if isNone(alg) {
            return jwt.UnsafeAllowNoneSignatureType, nil
        }
        switch {
        case isEs(alg):
            return jwt.ParseECPublicKeyFromPEM(publicKey)
        case isRs(alg):
            return jwt.ParseRSAPublicKeyFromPEM(publicKey)
        case isEd(alg):
            return jwt.ParseEdPublicKeyFromPEM(publicKey)
        default:
            return publicKey, nil
        }
    })

    if err != nil {
        return nil, fmt.Errorf("couldn't parse token: %w", err)
    }

    return token.Claims, nil
}

// Print a json object in accordance with the prophecy (or the command line options)
func printJSON(j interface{}) error {
	var out []byte
	var err error
	out, err = json.Marshal(j)

	if err == nil {
		fmt.Println(string(out))
	}

	return err
}
func isEs(flagAlg string) bool {
	return strings.HasPrefix(flagAlg, "ES")
}

func isRs(flagAlg string) bool {
	return strings.HasPrefix(flagAlg, "RS") || strings.HasPrefix(flagAlg, "PS")
}

func isEd(flagAlg string) bool {
	return flagAlg == "EdDSA"
}

func isNone(flagAlg string) bool {
	return flagAlg == "none"
}