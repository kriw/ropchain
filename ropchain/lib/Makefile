CC = g++
RM = rm
CPPFLAGS = -std=c++17

EXECUTABLE = ./bin/ropchain
MODULE = ./lib/ropchain
SRC_DIRS = ./src/lib/

MODULE_MAIN = ./src/python_module/main.cpp
EXE_MAIN = ./src/main.cpp
SRCS := $(shell find $(SRC_DIRS) -name *.cpp)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)
INCS := $(shell pkg-config --cflags r_socket)
LIBS := $(shell pkg-config --libs r_socket)
#FIXME
MODULE_INC = -I/usr/include -I/usr/include/python
#FIXME
MODULE_LIB = $(shell find /usr/lib/ -maxdepth 2 -name 'libboost*' | sed -e 's/.*\/lib/-l/' | cut -d'.' -f1)
# MODULE_LIB += $(shell find /usr/lib/python/ -maxdepth 3 -name '*.so'| sed -e 's/.*\/lib/-l/' | cut -d'.' -f1)
OPS  := -Wall -Wextra

.PHONY: all
all: exe module

.PHONY: exe
exe: $(EXECUTABLE)

$(EXECUTABLE): $(EXE_MAIN) $(OBJS)
	$(CC) $(INCS) $(CPPFLAGS) $(LIBS) -o $(EXECUTABLE) $(EXE_MAIN) $(OBJS)

.PHONY: module
module: $(MODULE)

$(MODULE): $(MODULE_MAIN) $(OBJS)
	$(CC) $(CPPFLAGS) $(INCS) $(MODULE_INC) $(MODULE_LIB) $(LIBS) -o $(MODULE) $(MODULE_MAIN) $(OBJS)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

.cpp.o:
	$(CC) -g $(OPS) $(CPPFLAGS) $(INCS) -c $< -o $@
