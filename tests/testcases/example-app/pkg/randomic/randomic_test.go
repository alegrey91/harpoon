package randomic

import (
	"testing"
)

func TestRockPaperScissors(t *testing.T) {
	tests := []struct {
		name     string
		expected []string
	}{
		{"Valid Choice", []string{"rock", "paper", "scissors"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := RockPaperScissors()
			isValid := false
			for _, validChoice := range test.expected {
				if result == validChoice {
					isValid = true
					break
				}
			}
			if !isValid {
				t.Errorf("Got %s, but expected one of %v", result, test.expected)
			}
		})
	}
}

func TestThrowDice(t *testing.T) {
	tests := []struct {
		name          string
		facesNumber   int
		expectedMin   int
		expectedMax   int
		expectedError bool
	}{
		{
			"test_1",
			4,
			1,
			4,
			false,
		},
		{
			"test_2",
			6,
			1,
			6,
			false,
		},
		{
			"test_3",
			5,
			0,
			0,
			true,
		},
		{
			"test_4",
			10,
			1,
			10,
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ThrowDice(test.facesNumber)
			if err != nil && !test.expectedError {
				t.Errorf("Got unexpected error: %v", err)
			}
			if result < test.expectedMin || result > test.expectedMax {
				t.Errorf("Got %d, but expected a value between %d and %d", result, test.expectedMin, test.expectedMax)
			}
		})
	}
}

func TestFlipCoin(t *testing.T) {
	tests := []struct {
		name     string
		expected []string
	}{
		{"Valid Choice", []string{"head", "tail"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := FlipCoin()
			isValid := false
			for _, validChoice := range test.expected {
				if result == validChoice {
					isValid = true
					break
				}
			}
			if !isValid {
				t.Errorf("Got %s, but expected one of %v", result, test.expected)
			}
		})
	}
}

func TestDoSomethingSpecial(t *testing.T) {
	tests := []struct {
		name     string
		value    int
		expected bool
	}{
		{
			name:     "test1",
			value:    1000,
			expected: true,
		},
		{
			name:     "test2",
			value:    0,
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			DoSomethingSpecial(test.value)
			if !test.expected {
				t.Errorf("Got an error")
			}
		})
	}
}

func TestDoNothing(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "this test doesn't test anything",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DoNothing(); got != tt.want {
				t.Errorf("DoNothing() = %v, want %v", got, tt.want)
			}
		})
	}
}
