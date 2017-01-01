package main

import (
	"fmt"
	"log"

	"github.com/Code-Hex/go-github-token"
)

func main() {
	c := token.New()
	t, err := c.GetAccessToken()
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("Got: " + t)
}
