package main

import (
	"fmt"
	"os"
)

func subCommandHelp() {
	fmt.Println("expected 'singleSubtree' or 'singleSubtreeStats' or 'parallelSubtree' or 'parallelSubtreeStats'")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		subCommandHelp()
	}

	switch os.Args[1] {

	case "singleSubtree":
		singleSubtree()
	case "singleSubtreeStats":
		singleSubtreeStats()
	case "parallelSubtree":
		parallelSubtree()
	case "parallelSubtreeStats":
		parallelSubtreeStats()
	default:
		subCommandHelp()
	}
}
