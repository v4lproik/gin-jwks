package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	. "github.com/v4lproik/gin-jwks"
)

func main() {
	r := gin.Default()

	builder := NewConfigBuilder()
	config, err := builder.
		NewPrivateKey().
		WithKeyId("my-id").
		WithKeyLength(2048).
		Build()

	if err != nil {
		fmt.Errorf("error generating conf %v", err)
		return
	}

	r.GET("/.well-known/jwks.json", Jkws(*config))
	r.Run()
}
