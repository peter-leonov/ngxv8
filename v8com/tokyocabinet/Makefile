CC			= gcc
CFLAGS		=
CPPFLAGS	=
OBJS		= tchdb.o
INCLUDES	= -I/Users/rykomats/sandbox/v8/include \
			  -I/Users/rykomats/build/tokyocabinet/include
LIBS		= -L/Users/rykomats/sandbox/v8 -lv8 \
			  -L/Users/rykomats/build/tokyocabinet/lib -ltokyocabinet \
			  -lstdc++

tchdb.dylib: $(OBJS)
	$(CC) -dynamiclib -o $@ $(OBJS) $(LIBS)

.cc.o:
	$(CC) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $<

tchdb.o: tchdb.h

all: tchdb.dylib

clean:
	rm -rf tchdb.dylib *.o
