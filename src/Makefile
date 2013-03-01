CFLAGS        = -Wall -DXP_UNIX=1 -DMOZ_X11=1 -fPIC -g -std=c99
LIBS          = -lssl -lcrypto
OBJS          = BasicPlugin.o jsrsa.o jsaes.o scriptable.o np_array.o
TARGET        = libcryptoplugin.so

all: $(TARGET)

$(TARGET) : $(OBJS)
	cc $(CFLAGS) -shared $(OBJS) -o $@ $(LIBS)

.c.o:
	$(CC) -c -g -pg $(CFLAGS) $<

BasicPlugin.o: BasicPlugin.h
jsrsa.o: jsrsa.h
jsaes.o: jsaes.h
scriptable.o: scriptable.h
np_array.o: np_array.h

clean :
	rm *.so *.o

