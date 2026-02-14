// JWKS server entrypoint (Project 1)
package main
import (
	"log"

	"jwks-server/internal/httpapi"
	"jwks-server/internal/keys"
)

func main() {
	km, err := keys.NewDefaultKeyManager()
	if err != nil {
		log.Fatalf("failed to init keys: %v", err)
	}

	srv := httpapi.NewServer(km)

	log.Println("JWKS server listening on :8080")
	if err := srv.ListenAndServe(":8080"); err != nil {
		log.Fatalf("server error: %v", err)
	}
}