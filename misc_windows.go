package main

import "fmt"

const (
	useRawTerminal bool = false
)

func (self *shell) printf(format string, a ...any) (n int, err error) {
	return fmt.Printf(format, a...)
}

func (self *shell) println(a ...any) (n int, err error) {
	return fmt.Println(a...)
}
