CC			= gcc
CFLAGS		=
CPPFLAGS	=
OBJS		= clearsilver.o
INCLUDES	= -I/Users/rykomats/sandbox/v8/include \
			  -I/Users/rykomats/build/clearsilver/include/ClearSilver
LIBS		= -L/Users/rykomats/sandbox/v8 -lv8 \
			  -L/Users/rykomats/build/clearsilver/lib -lneo_cs -lneo_utl \
			  -lstdc++

clearsilver.dylib: $(OBJS)
	$(CC) -dynamiclib -o $@ $(OBJS) $(LIBS)

.cc.o:
	$(CC) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $<

clearsilver.o: clearsilver.h

all: clearsilver.dylib

clean:
	rm -rf clearsilver.dylib *.o
