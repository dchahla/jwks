## Basic Usage Example
	
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

  
	AUDIENCE := os.Getenv("AUDIENCE") //  define audience (string)
	keys := jwks.InitKeySet() 

	middleware := jwks.Verify(AUDIENCE, "RS256", &keys) // set up middleware to use audience and keys
