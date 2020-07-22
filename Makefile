all:
	mkdir -p build
	go build -o ./build/oidcapp ./cmd

clean:
	rm -rf ./build
