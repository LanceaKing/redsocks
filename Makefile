# The executable is a thin caller of the same shared core as Android/JNI.
CMAKE ?= cmake
BUILD_DIR ?= build
.PHONY: all clean distclean test tests/prlimit-nofile
all:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build $(BUILD_DIR) -j4
	ln -sf $(BUILD_DIR)/redsocks redsocks

tests/prlimit-nofile:
	$(CC) -std=c99 -D_GNU_SOURCE -Wall tests/prlimit-nofile.c -o $@

test: all tests/prlimit-nofile
	tests/run

clean:
	$(CMAKE) --build $(BUILD_DIR) --target clean

distclean:
	rm -rf $(BUILD_DIR)
	rm -f redsocks tests/prlimit-nofile
