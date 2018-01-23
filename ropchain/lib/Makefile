CC = g++
RM = rm
CPPFLAGS = -std=c++17

TARGET = ./bin/ropchain
SRC_DIRS = ./src

SRCS := $(shell find $(SRC_DIRS) -name *.cpp)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)
INCS := $(shell pkg-config --cflags r_socket)
LIBS := $(shell pkg-config --libs r_socket)
OPS  := -Wall -Wextra

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(INCS) $(LIBS) -o $(TARGET) $(OBJS)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

.cpp.o:
	$(CC) -g $(OPS) $(CPPFLAGS) $(INCS) -c $< -o $@
