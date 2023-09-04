package common

import (
	"fmt"
	"math"
)

func main() {
	// Calculate the square root of a number
	num := 16.0
	sqrt := math.Sqrt(num)
	fmt.Printf("The square root of %g is %g\n", num, sqrt)

	// Calculate the factorial of a number
	n := 5
	fact := factorial(n)
	fmt.Printf("The factorial of %d is %d\n", n, fact)
}

func factorial(n int) int {
	if n <= 0 {
		return 1
	}
	return n * factorial(n-1)
}
