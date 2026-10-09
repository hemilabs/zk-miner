# Portable Linux builds via Docker
#
# Usage:
#   make cli          Build the main zkminer binary
#   make cuda         Build RISC Zero CUDA prover
#   make rocm         Build RISC Zero ROCm prover
#   make sp1          Build SP1 prover
#   make openvm       Build OpenVM prover
#   make all          Build everything
#   make clean        Remove dist/ outputs
#   make distclean    Remove dist/ and prune Docker build cache
#   make e2e          Run end-to-end tests in Docker
#   make help         Show this help
#
# Override versions:
#   make cuda CUDA_VERSION=13.1.1
#   make rocm ROCM_IMAGE=rocm/dev-ubuntu-22.04:6.3

export DOCKER_BUILDKIT := 1

RUST_VERSION  ?= 1.93.0
CUDA_VERSION  ?= 12.8.0
ROCM_IMAGE    ?= rocm/dev-ubuntu-22.04:6.4
UBUNTU_VERSION ?= 22.04
FOUNDRY_VERSION ?= v1.3.5

PROGRESS ?= auto

DOCKER_BUILD = docker build -f Dockerfile.build \
	--progress=$(PROGRESS) \
	--build-arg RUST_VERSION=$(RUST_VERSION) \
	--build-arg CUDA_VERSION=$(CUDA_VERSION) \
	--build-arg ROCM_IMAGE=$(ROCM_IMAGE) \
	--build-arg UBUNTU_VERSION=$(UBUNTU_VERSION) \
	--build-arg FOUNDRY_VERSION=$(FOUNDRY_VERSION)

.PHONY: all cli cli-windows cuda rocm intel sp1 openvm clean distclean help test test-integration e2e

all: cli cuda rocm sp1 openvm

dist/zkminer: FORCE
	$(DOCKER_BUILD) --target dist-cli --output type=local,dest=dist/ .
	cd dist && sha256sum zkminer > zkminer.sha256

dist/zkminer-prove-risc0-cuda: FORCE
	$(DOCKER_BUILD) --target dist-cuda --output type=local,dest=dist/ .
	cd dist && sha256sum zkminer-prove-risc0-cuda > zkminer-prove-risc0-cuda.sha256

dist/zkminer-prove-risc0-rocm: FORCE
	$(DOCKER_BUILD) --target dist-rocm --output type=local,dest=dist/ .
	cd dist && sha256sum zkminer-prove-risc0-rocm > zkminer-prove-risc0-rocm.sha256

dist/zkminer-prove-sp1: FORCE
	$(DOCKER_BUILD) --target dist-sp1 --output type=local,dest=dist/ .
	cd dist && sha256sum zkminer-prove-sp1 > zkminer-prove-sp1.sha256

dist/sp1-gpu-server: FORCE
	$(DOCKER_BUILD) --target dist-sp1-server --output type=local,dest=dist/ .
	cd dist && sha256sum sp1-gpu-server > sp1-gpu-server.sha256 \
		&& sha256sum libcudart.so.12 > libcudart.so.12.sha256

dist/zkminer-prove-openvm: FORCE
	$(DOCKER_BUILD) --target dist-openvm --output type=local,dest=dist/ .
	cd dist && sha256sum zkminer-prove-openvm > zkminer-prove-openvm.sha256

dist/zkminer.exe: FORCE
	$(DOCKER_BUILD) --target dist-cli-windows --output type=local,dest=dist/ .
	cd dist && sha256sum zkminer.exe > zkminer.exe.sha256

cli: dist/zkminer
cli-windows: dist/zkminer.exe
cuda: dist/zkminer-prove-risc0-cuda
rocm: dist/zkminer-prove-risc0-rocm
# intel: dist/zkminer-prove-risc0-intel  # uncomment when sppark SYCL port is ready
sp1: dist/zkminer-prove-sp1 dist/sp1-gpu-server
openvm: dist/zkminer-prove-openvm

test:
	cargo test
	cargo test -p zkminer-prover --features testing --test worker_lifecycle

test-integration:
	cargo test -p zkminer-prover --features testing --test worker_lifecycle

# End-to-end tests, run inside the `e2e` Docker stage.
# Extra cargo test args: make e2e E2E_ARGS="smoke"
e2e:
	$(DOCKER_BUILD) --target e2e -t zkminer-e2e .
	docker run --rm -e ZKMINER_E2E_KEEP zkminer-e2e $(if $(E2E_ARGS),cargo test -p zkminer-e2e $(E2E_ARGS))

clean:
	rm -rf dist/

distclean: clean
	docker builder prune --filter type=exec.cachemount -f
	docker builder prune -f

help:
	@echo "Build targets:"
	@echo "  cli         - zkminer CLI binary (Linux)"
	@echo "  cli-windows - zkminer CLI binary (Windows .exe, cross-compiled)"
	@echo "  cuda     - RISC Zero CUDA prover (~2h build)"
	@echo "  rocm     - RISC Zero ROCm prover (~7h build)"
	@echo "  intel    - Intel GPU prover (placeholder, pending sppark SYCL port)"
	@echo "  sp1      - SP1 prover, and the sp1-gpu-server it ships with"
	@echo "  openvm   - OpenVM prover"
	@echo "  all      - Build all binaries"
	@echo "  test     - Run all tests (unit + integration)"
	@echo "  test-integration - Run worker lifecycle integration tests only"
	@echo "  e2e      - Run end-to-end tests in Docker (E2E_ARGS=... to filter)"
	@echo "  clean    - Remove dist/ directory"
	@echo "  distclean - Remove dist/ and prune Docker build cache"
	@echo ""
	@echo "Override versions:"
	@echo "  make cuda CUDA_VERSION=13.1.1"
	@echo "  make rocm ROCM_IMAGE=rocm/dev-ubuntu-22.04:6.3"
	@echo "  make cuda PROGRESS=plain    (full build output)"

FORCE:
