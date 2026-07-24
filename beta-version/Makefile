CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -I. -I/usr/include/node
LDFLAGS  = -L/usr/lib/x86_64-linux-gnu -l:libcrypto.so.3 -l:libargon2.so.1
TARGET   = pwmgr
SRC      = main.cpp

# Optional hardware second-factor support, independently toggleable:
#   make WITH_FIDO2=1
#   make WITH_TPM=1
#   make WITH_FIDO2=1 WITH_TPM=1
# Requires libfido2-dev / libtss2-dev (Debian/Ubuntu package names - see
# the build-instructions comment near the top of main.cpp for other
# distros). Fails fast with a clear message if pkg-config can't find the
# one you asked for, instead of leaving it to a cryptic compiler/linker
# error. Use the default target (plain "make"), not "standard", unless you
# specifically have libssl-dev/libargon2-dev (unversioned -dev symlinks)
# installed - "standard" links via -lcrypto/-largon2, the default target
# links the versioned .so directly and works without those -dev packages.
TSS2_MODULES = tss2-esys tss2-mu tss2-rc
ifeq ($(WITH_FIDO2),1)
  ifeq ($(shell pkg-config --exists libfido2 && echo yes),)
    $(error WITH_FIDO2=1 requested, but pkg-config can't find libfido2 - install libfido2-dev (Debian/Ubuntu), libfido2-devel (Fedora/RHEL), or libfido2 (macOS/brew))
  endif
  EXTRA_CXXFLAGS += -DPWMGR_WITH_FIDO2 $(shell pkg-config --cflags libfido2)
  EXTRA_LIBS     += $(shell pkg-config --libs libfido2)
endif
ifeq ($(WITH_TPM),1)
  ifeq ($(shell pkg-config --exists $(TSS2_MODULES) && echo yes),)
    $(error WITH_TPM=1 requested, but pkg-config can't find one of $(TSS2_MODULES) - install libtss2-dev (Debian/Ubuntu) or tpm2-tss-devel (Fedora/RHEL))
  endif
  EXTRA_CXXFLAGS += -DPWMGR_WITH_TPM $(shell pkg-config --cflags $(TSS2_MODULES))
  EXTRA_LIBS     += $(shell pkg-config --libs $(TSS2_MODULES))
endif

.PHONY: all clean install standard test

all: $(TARGET)

$(TARGET): $(SRC) argon2_min.h
	$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $< -o $@ $(LDFLAGS) $(EXTRA_LIBS)
	@echo "Built: ./$(TARGET)"

# Standard systems with libssl-dev + libargon2-dev:
#   sudo apt install libssl-dev libargon2-dev
standard: $(SRC) argon2_min.h
	$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $< -o $(TARGET) -lcrypto -largon2 $(EXTRA_LIBS)
	@echo "Built: ./$(TARGET)"

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

test: $(TARGET)
	chmod +x tests/test_smoke.sh
	./tests/test_smoke.sh
