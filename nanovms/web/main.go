package main

import (
    "fmt"
    "log"
    "net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
    // Write a message to the response body
    fmt.Fprintf(w, "Hello, World!")
}

func main() {
    // Register the handler function for the root path "/"
    http.HandleFunc("/", helloHandler)

    fmt.Println("Server starting at :8080")
    // Start the server and listen for incoming requests
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}
