ZIG ?= zig

LIBAEGIS_DIR := $(CURDIR)/src/c/libaegis
LIBAEGIS_BUILD := $(LIBAEGIS_DIR)/build.zig
LIBAEGIS_INPUTS := Makefile $(LIBAEGIS_BUILD) $(LIBAEGIS_DIR)/build.zig.zon \
	$(shell find "$(LIBAEGIS_DIR)/src" -type f \( -name '*.c' -o -name '*.h' \))
WASM_LIB_DIR := $(CURDIR)/wasm-libs
WASM_BUILD_FLAGS := -Dtarget=wasm32-freestanding -Drelease

BASELINE_LIBRARY := $(WASM_LIB_DIR)/libaegis.a
RELAXED_SIMD_LIBRARY := $(WASM_LIB_DIR)/libaegis_relaxed_simd.a
BASELINE_BUILD_DIR := $(CURDIR)/tmp/libaegis-wasm-baseline
RELAXED_SIMD_BUILD_DIR := $(CURDIR)/tmp/libaegis-wasm-relaxed-simd
BASELINE_PREFIX := $(BASELINE_BUILD_DIR)/install
RELAXED_SIMD_PREFIX := $(RELAXED_SIMD_BUILD_DIR)/install

.DELETE_ON_ERROR:
.PHONY: all wasm-libs clean-wasm-build

all: wasm-libs

wasm-libs: $(BASELINE_LIBRARY) $(RELAXED_SIMD_LIBRARY)

$(BASELINE_LIBRARY): $(LIBAEGIS_INPUTS)
	$(RM) -r "$(BASELINE_BUILD_DIR)"
	cd "$(LIBAEGIS_DIR)" && $(ZIG) build $(WASM_BUILD_FLAGS) \
		-Dwasm-relaxed-simd=false --prefix "$(BASELINE_PREFIX)"
	mkdir -p "$(WASM_LIB_DIR)"
	cp "$(BASELINE_PREFIX)/lib/libaegis.a" "$(BASELINE_BUILD_DIR)/libaegis.a"
	mv "$(BASELINE_BUILD_DIR)/libaegis.a" "$@"
	$(RM) -r "$(BASELINE_BUILD_DIR)"

$(RELAXED_SIMD_LIBRARY): $(LIBAEGIS_INPUTS)
	$(RM) -r "$(RELAXED_SIMD_BUILD_DIR)"
	cd "$(LIBAEGIS_DIR)" && $(ZIG) build $(WASM_BUILD_FLAGS) \
		-Dwasm-relaxed-simd=true --prefix "$(RELAXED_SIMD_PREFIX)"
	mkdir -p "$(WASM_LIB_DIR)"
	cp "$(RELAXED_SIMD_PREFIX)/lib/libaegis.a" \
		"$(RELAXED_SIMD_BUILD_DIR)/libaegis_relaxed_simd.a"
	mv "$(RELAXED_SIMD_BUILD_DIR)/libaegis_relaxed_simd.a" "$@"
	$(RM) -r "$(RELAXED_SIMD_BUILD_DIR)"

clean-wasm-build:
	$(RM) -r "$(BASELINE_BUILD_DIR)" "$(RELAXED_SIMD_BUILD_DIR)"
