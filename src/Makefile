ifeq ($(ARCH),i386)
	CFLAGS        = -Wall -DXP_MACOSX=1 -DMOZ_X11=1 -fPIC -g -std=c99 -arch i386
	LFLAGS        = -bundle -arch i386
else
	CFLAGS        = -Wall -DXP_MACOSX=1 -DMOZ_X11=1 -fPIC -g -std=c99 -arch x86_64
	LFLAGS        = -bundle -arch x86_64
endif

LIBS          = -lssl -lcrypto
OBJS          = BasicPlugin.o jsrsa.o scriptable.o
TARGET        = jscrypto_bundle

all: $(TARGET)

$(TARGET): jscrypto_bundle_dir jscrypto
	cp -f jscrypto jscrypto.bundle/Contents/MacOS/
	cp -f Info.plist jscrypto.bundle/Contents/
	cp -f -R English.lproj jscrypto.bundle/Contents/Resources/

jscrypto_bundle_dir:
	mkdir -p jscrypto.bundle
	mkdir -p jscrypto.bundle/Contents/Resources
	mkdir -p jscrypto.bundle/Contents/MacOS

jscrypto:$(OBJS)
	cc $(CFLAGS) $(LFLAGS) $(OBJS) -o $@ $(LIBS)

.c.o:
	$(CC) -c -g -pg $(CFLAGS) $<

BasicPlugin.o: BasicPlugin.h
jsrsa.o: jsrsa.h
scriptable.o: scriptable.h

clean :
	rm -rf *.so *.o jscrypto.bundle

