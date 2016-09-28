# Copyright (c) lnwdl (lnwdl@163.com)
# All rights reserved.
#
CC = gcc
ifeq (1, 1)
CFLAG = -c -g -DUSE_CRYPTO
LD_FILE = -lskf -lcrypto
else
CFLAG = -c -g
LD_FILE = -lskf
endif
TARGET = test
INC_DIR = -I . 
LD_DIR = -L lib
SRC_DIR = .

SRCS = $(notdir $(wildcard $(SRC_DIR)/*.c))

OBJS = $(patsubst %.c, %.o, $(SRCS))

%.o: $(join $(SRC_DIR)/, %.c)
	$(CC) -c $(CFLAG) $< -o $@ $(INC_DIR) $(LD_DIR)

all: dclean $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LD_DIR) $(LD_FILE)
	@echo ".......... OK"

clean: 
	rm -rf $(OBJS)

dclean: 
	rm -rf $(OBJS) $(TARGET)

