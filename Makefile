.PHONY: build install test clean

BINARY_NAME=yubivault
PROVIDER_NAME=terraform-provider-yubivault
PROVIDER_PATH=~/.terraform.d/plugins/registry.terraform.io/mmunier/yubivault/0.1.0/linux_amd64
INSTALL_DIR=~/.local/bin

build:
	go build -o $(BINARY_NAME) ./cmd/yubivault
	go build -o $(PROVIDER_NAME) .

install: build
	mkdir -p $(PROVIDER_PATH)
	cp $(PROVIDER_NAME) $(PROVIDER_PATH)/
	chmod +x $(PROVIDER_PATH)/$(PROVIDER_NAME)
	cp $(BINARY_NAME) $(INSTALL_DIR)/

test:
	go test -v ./...

integration_test:
	@echo YUBIKEY_PIN: ; \
	read -s YUBIKEY_PIN ; \
	YUBIKEY_PIN=$$YUBIKEY_PIN go test -tags=integration -v ./...

clean:
	rm -f $(BINARY_NAME) $(PROVIDER_NAME)
	rm -rf vault/

init-vault: build
	./$(BINARY_NAME) init

example: install
	cd examples/basic && yubivault run init && yubivault run plan

.DEFAULT_GOAL := build
