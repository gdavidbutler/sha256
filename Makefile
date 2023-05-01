CFLAGS=-I. -Os

all: sha256

clobber: clean
	rm -f sha256 shaby

clean:
	rm -f sha256.o

sha256: test/main.c sha256.o
	$(CC) $(CFLAGS) -o sha256 test/main.c sha256.o

sha256.o: sha256.c sha256.h
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=4 -c sha256.c

check: test/shaby.c sha256.c sha256.h
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=1 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256ShortMsg.rsp 
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=2 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256ShortMsg.rsp
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=3 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256ShortMsg.rsp
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=4 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256ShortMsg.rsp
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=1 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256LongMsg.rsp 
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=2 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256LongMsg.rsp
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=3 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256LongMsg.rsp
	$(CC) $(CFLAGS) -DSHA256_SPACETIME=4 -o shaby test/shaby.c sha256.c;./shaby < test/shabytetestvectors/SHA256LongMsg.rsp
