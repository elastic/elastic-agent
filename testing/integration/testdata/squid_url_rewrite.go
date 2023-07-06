package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	const fleetHost = "http://fleet.elastic.co"

	fmt.Println("started urlRewriter")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 1 {
			fmt.Println("ERR")
			continue
		}

		url := fields[0]
		actualFleetHost := fields[1]

		fmt.Print("OK ")
		if strings.HasPrefix(url, fleetHost) {
			fmt.Printf(`OK rewrite-url="%s"`,
				strings.Replace(url, fleetHost, actualFleetHost, 1))
		}
		fmt.Print("\n")
	}

	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", scanner.Err())
	}
}
