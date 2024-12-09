APP := packet-parser

CC      := g++
SRC_FMT := cpp
CFLAGS  := -O0 -g -Iinclude
LDFLAGS += -lpcap
LDFLAGS += -lmysqlcppconn

SRC_DIRS := src

SRCS := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.$(SRC_FMT)))
OBJS := $(patsubst %.$(SRC_FMT),bin/%.o,$(SRCS))
DEPS := $(patsubst %.$(SRC_FMT),bin/%.d,$(SRCS))

all: bin/$(APP)

bin/$(APP): $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

bin/%.o: %.$(SRC_FMT)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $@ -c $< -o $@

clean:
	@rm -rf bin $(APP)
