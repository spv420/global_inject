CC=clang
CC_ARM=xcrun -sdk iphoneos clang -arch armv7
CFLAGS_DYLIB=-dynamiclib
CFLAGS=
CFLAGS_OBJC=-fobjc-arc -fmodules -framework Foundation

all:	clean dylib bin/envbypass

dylib:
	${CC} ${CFLAGS_DYLIB} ${CFLAGS_OBJC} -o bin/game_over.dylib src/game_over.m
	${CC_ARM} ${CFLAGS_DYLIB} ${CFLAGS_OBJC} -o bin/game_over_armv7.dylib src/game_over.m

old: clean
	${CC} ${CFLAGS} ${CFLAGS_DYLIB} -o bin/game_over_old.dylib src/game_over.c
	${CC_ARM} ${CFLAGS} ${CFLAGS_DYLIB} -o bin/game_over_old_armv7.dylib src/game_over.c

bin/envbypass:
	${CC_ARM} ${CFLAGS} -o bin/envbypass src/envbypass.c
	ldid -Sent.xml bin/envbypass
	#${CC} ${CFLAGS} -o test test.c

clean:
	sh -c "rm -rf bin; echo"
	mkdir bin

install:
#	cat bin/game_over_objc_armv7.dylib | ssh root@localhost -p 2222 "cat > /untether/game_over_objc_armv7.dylib2; mv /untether/game_over_objc_armv7.dylib2 /untether/game_over_objc_armv7.dylib1"
	cat bin/game_over_armv7.dylib | ssh root@localhost -p 2222 "cat > /untether/game_over_armv7.dylib2; mv /untether/game_over_armv7.dylib2 /untether/game_over_armv7.dylib1"
	cat bin/envbypass | ssh root@localhost -p 2222 "cat > envbypass"