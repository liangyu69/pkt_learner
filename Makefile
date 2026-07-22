CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap
TARGET = pkt_learner
SRCS = src/main.c src/modules/tcp.c

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)