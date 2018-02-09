CC = g++
RM = rm
RPP = $(shell pwd)/src/common/frontend/rp++/rp_script.sh
OPS  := -Wall -Wextra -fPIC -std=c++17 -DRPP_PATH=\"$(RPP)\"
ifeq "$(findstring release, $(MAKECMDGOALS))" ""
	OPS += -g -D_DEBUG
else
	OPS += -O3
endif

PYTHON = python2.7
EXECUTABLE = ./bin/ropchain
MODULE = ./lib/ropchain.so
SRC_DIRS = ./src/common/

MODULE_MAIN = ./src/python_module/main.cpp
EXE_MAIN = ./src/executable/main.cpp
SRCS := $(shell find $(SRC_DIRS) -name *.cpp)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
INCS := $(shell pkg-config --cflags r_socket)
LIBS := $(shell pkg-config --libs r_socket)
MODULE_INC = -I/usr/include -I/usr/include/$(PYTHON)
MODULE_LIB = -lboost_python -l$(PYTHON)
MODULE_OPS = -shared -Wl,-soname,$(MODULE)

.PHONY: all
all: exe module

.PHONY: exe
exe: $(EXECUTABLE)

$(EXECUTABLE): $(EXE_MAIN) $(OBJS)
	$(CC) $(OPS) $(INCS) $(CPPFLAGS) $(EXE_MAIN) -o $(EXECUTABLE) $(OBJS) $(LIBS)

.PHONY: module
module: $(MODULE)

$(MODULE): $(MODULE_MAIN) $(OBJS)
	$(CC) $(OPS) $(CPPFLAGS) $(MODULE_OPS) $(MODULE_MAIN) -o $(MODULE) $(OBJS) $(INCS) $(MODULE_INC) $(MODULE_LIB) $(LIBS)

.PHONY: clean
clean:
	$(RM) $(EXECUTABLE) $(MODULE) $(OBJS)

.cpp.o:
	$(CC) $(OPS) $(CPPFLAGS) $(INCS) -c $< -o $@
