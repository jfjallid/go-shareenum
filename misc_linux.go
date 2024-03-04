package main

import "fmt"

const (
	useRawTerminal bool = true
)

func (self *shell) printf(format string, a ...any) (n int, err error) {
	output := fmt.Sprintf(format, a...)
	return self.t.Write([]byte(output))
}

func (self *shell) println(a ...any) (n int, err error) {
	output := fmt.Sprintln(a...)
	return self.t.Write([]byte(output))
}
