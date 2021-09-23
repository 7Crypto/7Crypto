# Flag
CC = gcc
CFLAGS = -O3 
LFLAGS = -O3

# Deafult option: release
# For debug option, USAGE: make /f Makefile2 DEBUG=1
ifeq ($(DEBUG), 1)
	# Debug mode, Rewrite the CFLAG and LFLAGS
	CFLAGS = -Wall -DDEBUG -g 
	LFLAGS = 
endif


# Files
BIN = sm4
OBJS = sm4.o sm4_ex.o main.o
SRCS = sm4.c sm4_ex.c main.c

# Targets
$(BIN) : $(OBJS)
	$(CC) $(LFLAGS) -o  sm4 $(OBJS)

clean:
	rm $(OBJS) $(BIN)

$(OBJS) : $(SRCS)
	$(CC) $(CFLAGS) -c sm4.c     -o sm4.o
	$(CC) $(CFLAGS) -c sm4_ex.c  -o sm4_ex.o
	$(CC) $(CFLAGS) -c main.c    -o main.o

	
