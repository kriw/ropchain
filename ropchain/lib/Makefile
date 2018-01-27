CC = g++
RM = rm
CPPFLAGS = -std=c++17
OPS  := -Wall -Wextra -fPIC
PYTHON = python2.7

EXECUTABLE = ./bin/ropchain
MODULE = ./lib/libropchain.so
SRC_DIRS = ./src/lib/

MODULE_MAIN = ./src/python_module/main.cpp
EXE_MAIN = ./src/main.cpp
SRCS := $(shell find $(SRC_DIRS) -name *.cpp)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
INCS := $(shell pkg-config --cflags r_socket)
LIBS := $(shell pkg-config --libs r_socket)
MODULE_INC = -I/usr/include -I/usr/include/python
MODULE_LIB = -lboost_python
MODULE_LIB += -l$(PYTHON)
MODULE_OPS := -shared -Wl,--export-dynamic

.PHONY: all
all: exe module

.PHONY: exe
exe: $(EXECUTABLE)

$(EXECUTABLE): $(EXE_MAIN) $(OBJS)
	$(CC) $(OPS) $(INCS) $(CPPFLAGS) $(EXE_MAIN) $(OBJS) $(LIBS) -o $(EXECUTABLE)

.PHONY: module
module: $(MODULE)

$(MODULE): $(MODULE_MAIN) $(OBJS)
	$(CC) $(OPS) $(CPPFLAGS) $(MODULE_OPS) $(MODULE_MAIN) $(OBJS) $(INCS) $(MODULE_INC) $(MODULE_LIB) $(LIBS) -o $(MODULE)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS)

.cpp.o:
	$(CC) -g $(OPS) $(CPPFLAGS) $(INCS) -c $< -o $@
