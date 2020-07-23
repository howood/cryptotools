.PHONY: test, testv, cover

test:
	export GOPROXY="https://proxy.golang.org" && export GO111MODULE=on && go test ./...

testv:
	export GOPROXY="https://proxy.golang.org" && export GO111MODULE=on && go test ./... -v

cover:
#	go test -coverprofile=cover.out ./ && go tool cover -html=cover.out -o cover.html
	go test -coverprofile=coverencrypter.out ./internal/encrypter/ && go tool cover -html=coverencrypter.out -o coverencrypter.html
	go test -coverprofile=coverparser.out ./internal/parser/ && go tool cover -html=coverparser.out -o coverparser.html
	go test -coverprofile=covergenerator.out ./internal/generator/ && go tool cover -html=covergenerator.out -o covergenerator.html
	go test -coverprofile=covercommonkeycrypto.out ./pkg/commonkeycrypto/ && go tool cover -html=covercommonkeycrypto.out -o covercommonkeycrypto.html
	go test -coverprofile=coverpublickeycrypto.out ./pkg/publickeycrypto/ && go tool cover -html=coverpublickeycrypto.out -o coverpublickeycrypto.html
