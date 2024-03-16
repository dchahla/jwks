## How does it work?
Pulls modulus from "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"


## Basic Example
	
	import (
		...
		"github.com/dchahla/jwks"
	  	"github.com/gorilla/mux"
		"github.com/joho/godotenv"
  		"github.com/rs/cors"

	)

	router := mux.NewRouter()
	router.Use(cors.New(cors.Options{
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler)

	//  define audience (string)
	AUDIENCE := os.Getenv("AUDIENCE")

	//  cache public keys
	keys := jwks.InitKeySet() 

	//  set up middleware to use audience and keys
	middleware := jwks.Verify(AUDIENCE, "RS256", &keys)

	//  release the hounds! (apply the middleware.)
	router.PathPrefix("/api/v1/app/delegation/groups").Handler(middleware(http.HandlerFunc(getGroupsHandler)))

