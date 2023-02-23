all:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o go-shareenum
	GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o go-shareenum.exe .

clean:
	rm -f go-shareenum
	rm -f go-shareenum.exe
