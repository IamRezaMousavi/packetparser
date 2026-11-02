PROJECT := packetparser

SRC_DIR   := src
INC_DIR   := include
BUILD_DIR := build

MARIADB_CFLAGS := $(shell pkg-config --cflags libmariadb)
MARIADB_LIBS   := $(shell pkg-config --libs libmariadb)


CC       := cc
CCX      := c++
CFLAGS   := -O2 -Wall -Wextra $(MARIADB_CFLAGS)
CXXFLAGS := $(CFLAGS) -std=c++20
LDFLAGS  :=
LIBS     := $(MARIADB_LIBS)

TARGETS := $(BUILD_DIR)/$(PROJECT)

C_SRCS   := $(wildcard $(SRC_DIR)/*.c)
CPP_SRCS := $(wildcard $(SRC_DIR)/*.cpp)
HDRS     := $(wildcard $(INC_DIR)/*.h $(INC_DIR)/*.hpp)

C_OBJS   := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(CPP_SRCS))
OBJS     := $(C_OBJS) $(CPP_OBJS)

C_DEPS   := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.d,$(C_SRCS))
CPP_DEPS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.d,$(CPP_SRCS))
DEPS     := $(C_DEPS) $(CPP_DEPS)

Q := @
E := $(Q)echo

all: prepare $(TARGETS)

prepare:
	$(Q) mkdir -p $(BUILD_DIR)

$(TARGETS): $(OBJS)
	$(E) "  LINK     " $@
	$(Q) $(CCX) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(E) "  CC       " $<
	$(Q) $(CC) $(CFLAGS) -I$(INC_DIR) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $@ -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(E) "  CCX      " $<
	$(Q) $(CXX) $(CXXFLAGS) -I$(INC_DIR) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $@ -c $< -o $@

clean:
	$(E) "  CLEAN"
	$(Q) rm -rf $(BUILD_DIR)

-include $(DEPS)

.PHONY: all prepare clean
