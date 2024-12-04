package randomic

import (
	"fmt"
	"math/rand"
	"syscall"
	"time"
)

// RockPaperScissors returns a random choice among "rock", "paper", and "scissors".
func RockPaperScissors() string {
	choices := []string{"rock", "paper", "scissors"}
	rand.Seed(time.Now().UnixNano())
	fmt.Println("[rock paper scissors]")
	return choices[rand.Intn(len(choices))]
}

// ThrowDice returns a random number between 1 and 6.
func ThrowDice(facesNumber int) (int, error) {
	allowedNumberOfFaces := map[int]bool{
		4:  true,
		6:  true,
		8:  true,
		10: true,
		12: true,
		20: true,
	}
	if !allowedNumberOfFaces[facesNumber] {
		return 0, fmt.Errorf("invalid number of faces")
	}
	rand.Seed(time.Now().UnixNano())
	fmt.Println("[throw dice]")
	return rand.Intn(facesNumber) + 1, nil
}

// FlipCoin returns either "head" or "tail" randomly.
func FlipCoin() string {
	choices := []string{"head", "tail"}
	rand.Seed(time.Now().UnixNano())
	fmt.Println("[flip coin]")
	return choices[rand.Intn(len(choices))]
}

func DoSomethingSpecial(value int) bool {
	syscall.Gettid()
	return true
}

func DoForAWhile() {
	for {
		fmt.Println("hello!")
		time.Sleep(2*time.Second)
	}
}
