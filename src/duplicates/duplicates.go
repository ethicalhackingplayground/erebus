package duplicates

var tested = make(chan string)

func GetTested() (tested chan string) {
	return tested
}

func SetTested(t string) {
	tested <- t
}
