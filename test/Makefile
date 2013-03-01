CC            = gcc -std=c99
CFLAGS        = -Wall
LDFLAGS       = -L../src
LIBS          = -lcryptoplugin
TEST_OBJS     = test.o
TEST          = test.out

all: $(TEST)

$(TEST) : $(OBJS) $(TEST_OBJS)
	$(CC) -g -pg -o $@ $(TEST_OBJS) $(OBJS) $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) -c -g -pg $(CFLAGS) $<

clean:
	rm -f *.o *~ *.out *.pem

