.PHONY: check
check:
	cargo check

.PHONY: clippy
clippy:
	cd ./TNLS-Gateways/secret && cargo clippy
	cd ./TNLS-Gateways/secret/tests/example-private-contract && cargo clippy
	cd ./TNLS-Samples/millionaires && cargo clippy

PHONY: test
test: unit-test

.PHONY: unit-test
unit-test:	
	cd ./TNLS-Gateways/secret && cargo unit-test
	cd ./TNLS-Gateways/secret/tests/example-private-contract && cargo unit-test
	cd ./TNLS-Samples/millionaires && cargo unit-test

# This is a local build with debug-prints activated. Debug prints only show up
# in the local development chain (see the `start-server` command below)
# and mainnet won't accept contracts built with the feature enabled.
.PHONY: build _build
build: _build
_build:
	cd ./TNLS-Gateways/secret && RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --features="debug-print" && make compress-wasm
	cd ./TNLS-Gateways/secret/tests/example-private-contract && RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --features="debug-print" && make compress-wasm
	cd ./TNLS-Samples/millionaires && RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --features="debug-print" && make compress-wasm
	
# This is a build suitable for uploading to mainnet.
# Calls to `debug_print` get removed by the compiler.
.PHONY: build-mainnet _build-mainnet
build-mainnet: _build-mainnet compress-wasm
_build-mainnet:
	cd ./TNLS-Gateways/secret && RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown
	cd ./TNLS-Gateways/secret/tests/example-private-contract && RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown
	cd ./TNLS-Samples/millionaires && RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown

# like build-mainnet, but slower and more deterministic
.PHONY: build-mainnet-reproducible
build-mainnet-reproducible:
	cd ./TNLS-Gateways/secret && \
	docker run --rm -v "$$(pwd)":/contract \
		--mount type=volume,source="$$(basename "$$(pwd)")_cache",target=/contract/target \
		--mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
		enigmampc/secret-contract-optimizer:1.0.9

# .PHONY: compress-wasm
# compress-wasm:
# 	cp ./target/wasm32-unknown-unknown/release/*.wasm ./contract.wasm
# 	@# The following line is not necessary, may work only on linux (extra size optimization)
# 	@# find . -name \contract.wasm -type f -exec wasm-opt -Os {} -o {} \; 
# 	find . -name \contract.wasm -type f -exec gzip -9kf {} \; 

.PHONY: schema
schema:
	cd ./TNLS-Gateways/secret && make schema
	cd ./TNLS-Gateways/secret/tests/example-private-contract && make schema
	cd ./TNLS-Samples/millionaires && make schema

# Run local development chain with four funded accounts (named a, b, c, and d)
.PHONY: start-server
start-server: # CTRL+C to stop
	docker run -it --rm \
		-p 26657:26657 -p 26656:26656 -p 1317:1317 -p 5000:5000 \
		-v $$(pwd):/root/code \
		--name localsecret ghcr.io/scrtlabs/localsecret:1.3.1

# This relies on running `start-server` in another console
# You can run other commands on the secretcli inside the dev image
# by using `docker exec localsecret secretcli`.
.PHONY: store-contract-local
store-contract-local:
	docker exec localsecret secretcli tx compute store -y --from a --gas 2000000 /root/code/contract.wasm.gz

# .PHONY: integration-test
# integration-test:
# 	npx ts-node tests/integration.ts

.PHONY: clean
clean:
	cargo clean
	-rm -f *.wasm
	-rm -f *.wasm.gz
