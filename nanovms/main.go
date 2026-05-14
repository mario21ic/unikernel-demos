package main

import (
	"fmt"
	"net/http"
)

func main() {
	// 1. Register a handler for the root path ("/")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})

	// 2. Start the server on port 8080
	fmt.Println("Server starting on :8080...")
	http.ListenAndServe(":8080", nil)
}

