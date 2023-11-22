all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-shareenum
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-shareenum.exe

clean:
	rm -f go-shareenum
	rm -f go-shareenum.exe
