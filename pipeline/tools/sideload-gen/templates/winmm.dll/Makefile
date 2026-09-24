# Cross-compile sideload proxy for winmm.dll
# Usage:  make            (builds winmm.dll)
#         make clean      (removes build artifacts)
#
# Requires: x86_64-w64-mingw32-gcc (MinGW-w64 toolchain)

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra
LDFLAGS = -shared -s
TARGET  = winmm.dll
SRC     = proxy.c
DEF     = proxy.def

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(DEF) shellcode.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(DEF)

clean:
	rm -f $(TARGET)

# Deployment reminder:
#   1. Rename the real winmm.dll -> winmm_orig.dll
#   2. Copy $(TARGET) as winmm.dll beside the host executable
#   3. Ensure winmm_orig.dll is in the same directory
