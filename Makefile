all:  docker TLSproxy.osx.amd64
bin: TLSproxy.osx.amd64 TLSproxy.linux.amd64

TLSproxy.linux.amd64: *.go
	env GOOS=linux GOARCH=amd64 go build -o TLSproxy.linux.amd64

TLSproxy.osx.amd64: *.go
	go build -o TLSproxy.osx.amd64

docker: *.go
	docker build -t tlsproxy/tlsproxy .

clean:
	rm -f TLSproxy.*

cleaner: clean
	rm -rf certs
	docker images | grep '<none>' | awk '{ print $3 }' | xargs docker rmi
