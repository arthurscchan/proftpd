#!/bin/bash -eu

export LDFLAGS="${CFLAGS}"
./configure --enable-ctrls
make -j$(nproc)

# We need a few declarations from main.c
# so we rename main() to main2()
sed 's/int main(/int main2(/g' -i $SRC/proftpd/src/main.c

# make_ftp_cmd() is static; de-static it so fuzz-ftp-cmd can call it.
sed 's/^static cmd_rec \*make_ftp_cmd(/cmd_rec *make_ftp_cmd(/' -i $SRC/proftpd/src/main.c

# Compile main.c again
export NEW_CC_FLAG="${CC} ${CFLAGS} -DHAVE_CONFIG_H -DLINUX  -I. -I./include"
$NEW_CC_FLAG -c src/main.c -o src/main.o
rm src/ftpdctl.o

find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

# Build fuzzer(s)
$NEW_CC_FLAG -c $SRC/fuzzer.c -o fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o -o $OUT/fuzzer \
	src/scoreboard.o \
	lib/prbase.a \
	fuzz_lib.a \
	-L/src/proftpd/lib \
	-lcrypt -pthread

$NEW_CC_FLAG -c tests/fuzzing/fuzz-ftp-cmd.c -o fuzz-ftp-cmd.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-ftp-cmd.o -o $OUT/fuzz-ftp-cmd \
	src/scoreboard.o \
	lib/prbase.a \
	fuzz_lib.a \
	-L/src/proftpd/lib \
	-lcrypt -pthread

# Build seed corpus
cd $SRC
git clone https://github.com/dvyukov/go-fuzz-corpus
zip $OUT/fuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/*

mkdir -p $SRC/ftp-cmd-corpus
printf 'USER anonymous' > $SRC/ftp-cmd-corpus/user
printf 'RETR /etc/passwd' > $SRC/ftp-cmd-corpus/retr
printf 'CWD ../../etc' > $SRC/ftp-cmd-corpus/cwd
printf 'PORT 127,0,0,1,7,138' > $SRC/ftp-cmd-corpus/port
printf 'SITE CHMOD 777 file with spaces' > $SRC/ftp-cmd-corpus/site
printf 'GET / HTTP/1.1' > $SRC/ftp-cmd-corpus/http
printf 'SSH-2.0-OpenSSH' > $SRC/ftp-cmd-corpus/ssh2
zip -j $OUT/fuzz-ftp-cmd_seed_corpus.zip $SRC/ftp-cmd-corpus/*

