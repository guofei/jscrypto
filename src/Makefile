CFLAGS        = -Wall -DXP_UNIX=1 -DMOZ_X11=1 -fPIC -g -std=c99
LIBS          = -lssl -lcrypto
OBJS          = BasicPlugin.o jsrsa.o
TARGET        = libcryptoplugin.so

all: $(TARGET)

$(TARGET) : $(OBJS)
	cc $(CFLAGS) -shared $(OBJS) -o $@ $(LIBS)

.c.o:
	$(CC) -c -g -pg $(CFLAGS) $<

BasicPlugin.o: BasicPlugin.h
jsrsa.o: jsrsa.h

clean :
	rm *.so *.o

