# Usage
	
	import (
		...
		"github.com/dchahla/jwks"
	)
	 
	AUDIENCE := os.Getenv("AUDIENCE") //  define audience (string)
	keys := jwks.InitKeySet() // cache public keys
	middleware := jwks.Verify(AUDIENCE, "RS256", &keys) // set up middleware to use audience and keys
