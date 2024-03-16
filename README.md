##usage
	
	import (
		...
		"github.com/dchahla/jwks"
	 	...
	)
	 
	AUDIENCE := os.Getenv("AUDIENCE") //  define audience (string)
	keys := jwks.InitKeySet() 

