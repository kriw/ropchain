CC = g++
RM = rm
CPPFLAGS = -std=c++17
TARGET = ./bin/ropchain
SRC_DIRS = ./src

SRCS := $(shell find $(SRC_DIRS) -name *.cpp)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)

# INC_DIRS := $(shell find $(SRC_DIRS) -type d)
# INC_FLAGS := $(addprefix -I,$(INC_DIRS))


$(TARGET): $(OBJS)
		$(CC) $(CPPFLAGS) $(OBJS) -o $@ $(LOADLIBES) $(LDLIBS)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)

