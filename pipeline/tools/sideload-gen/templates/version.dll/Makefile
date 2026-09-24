# Cross-compile sideload proxy for version.dll
# Usage:  make            (builds version.dll)
#         make clean      (removes build artifacts)
#
# Requires: x86_64-w64-mingw32-gcc (MinGW-w64 toolchain)

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra
LDFLAGS = -shared -s
TARGET  = version.dll
SRC     = proxy.c
DEF     = proxy.def

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(DEF) shellcode.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(DEF)

clean:
	rm -f $(TARGET)

# Deployment reminder:
#   1. Rename the real version.dll -> version_orig.dll
#   2. Copy $(TARGET) as version.dll beside the host executable
#   3. Ensure version_orig.dll is in the same directory
