package main

import "fmt"

const (
	useRawTerminal bool = true
)

func (self *shell) printf(format string, a ...any) (n int, err error) {
	if self.batch || self.t == nil {
		return fmt.Printf(format, a...)
	}
	output := fmt.Sprintf(format, a...)
	return self.t.Write([]byte(output))
}

func (self *shell) println(a ...any) (n int, err error) {
	if self.batch || self.t == nil {
		return fmt.Println(a...)
	}
	output := fmt.Sprintln(a...)
	return self.t.Write([]byte(output))
}
