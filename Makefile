build:
	go build -o ./bin/yum

PHONY: install_air
install_air:
	go install github.com/air-verse/air@latest

PHONY: air
air:
	air
