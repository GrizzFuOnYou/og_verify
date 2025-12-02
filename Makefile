# =============================================================================
# OG_VERIFY MAKEFILE
# =============================================================================
#
# This Makefile builds the og_verify tool for DJI firmware verification
# and decryption. It supports both native x86 builds and cross-compilation
# for ARM (Android) targets.
#
# TARGETS
# -------
#   make            Build og_verify for x86 (default)
#   make ARCH=arm   Build og_verify for ARM/Android
#   make clean      Remove all build artifacts
#
# CROSS-COMPILATION FOR ANDROID
# -----------------------------
# To build for Android devices (e.g., DJI drones with Android OS):
#
#   make ARCH=arm NDK_BUNDLE=/path/to/android-ndk
#
# Requirements:
#   - Android NDK (Native Development Kit)
#   - ARM cross-compiler toolchain from the NDK
#
# The ARM build uses:
#   - arm-linux-androideabi-gcc compiler
#   - Android API level 16 (Android 4.1 Jelly Bean)
#
# COMPILER FLAGS
# --------------
# -O3              Maximum optimization for speed
# -Isrc            Include path for header files
# -Wno-multichar   Suppress warnings about 'SLAK' style multi-char constants
#
# OUTPUT
# ------
# Produces: og_verify (executable)
#
# SOURCE FILES
# ------------
# src/verify.c  - Main verification logic and entry point
# src/rsa.c     - RSA signature verification (Montgomery multiplication)
# src/sha.c     - SHA-1 hash implementation (legacy, for compatibility)
# src/sha256.c  - SHA-256 hash implementation (used for DJI signatures)
# src/aes.c     - AES encryption/decryption (for payload decryption)
#
# =============================================================================

# Default architecture is x86 (native build)
# Override with: make ARCH=arm
ARCH ?= x86

# Android NDK location (required for ARM cross-compilation)
# This is the default path for macOS Android Studio installation
NDK_BUNDLE ?= $(HOME)/Library/Android/sdk/ndk-bundle

# Host platform for NDK tools (darwin = macOS, linux = Linux)
HOST ?= darwin-x86_64

# ARM cross-compilation configuration
ifeq ($(ARCH), arm)
  # Use ARM cross-compiler from Android NDK
  CROSS_COMPILE = $(NDK_BUNDLE)/toolchains/arm-linux-androideabi-4.9/prebuilt/$(HOST)/bin/arm-linux-androideabi-
  
  # Include paths for ARM target headers
  CFLAGS =  -I$(NDK_BUNDLE)/sysroot/usr/include/arm-linux-androideabi
  CFLAGS += -I$(NDK_BUNDLE)/sysroot/usr/include
  
  # Suppress common warnings in this codebase
  CFLAGS += -Wno-multichar -Wno-attributes
  
  # Link against Android system libraries
  LDFLAGS += --sysroot=$(NDK_BUNDLE)/platforms/android-16/arch-arm
  
  # Strip symbols for smaller binary
  LDFLAGS += -s
endif

# Compiler selection (uses cross-compiler prefix for ARM)
CC = $(CROSS_COMPILE)gcc

# Common compiler flags
# -Isrc: Find headers in src/ directory
# -O3: Maximum optimization
CFLAGS += -Isrc -O3

# =============================================================================
# Build Rules
# =============================================================================

# Pattern rule: compile .c files to .o object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Main target: link all object files into the og_verify executable
og_verify: src/verify.o src/rsa.o src/sha.o src/sha256.o src/aes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean target: remove all build artifacts
clean:
	rm -f og_verify src/*.o

# Phony targets (not actual files)
.PHONY: clean
