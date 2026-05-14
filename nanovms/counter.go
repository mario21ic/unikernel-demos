package main

import (
	"fmt"
	"time"
)

func main() {
	// Loop from 1 to 1000
	for i := 1; i <= 1000; i++ {
		fmt.Println("Counter:", i)
		// Sleep for 1 second
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Done!")
}

