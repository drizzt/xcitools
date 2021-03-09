CPPFLAGS += -D_FILE_OFFSET_BITS=64
CXXFLAGS ?= -Ofast -march=native
LDFLAGS  ?= -Wl,-O1
LIBS = -lcrypto

all: xcitools

xcitools: xcitools.cpp crc32/Crc32.cpp windows-mmap.cpp
	$(CC) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS)

clean:
	rm -f xcitools xcitools.exe
