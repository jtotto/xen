XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_xeninclude)

CFLAGS += -Wno-declaration-after-statement

TARGETS-y := mem-daemon
TARGETS := $(TARGETS-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS)

.PHONY: distclean
distclean: clean

mem-daemon: mem-daemon.o Makefile
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl)          \
                              $(LDLIBS_libxenforeignmemory) \
                              $(LDLIBS_libxenguest)         \
                              $(LDLIBS_libxenevtchn)

-include $(DEPS)
