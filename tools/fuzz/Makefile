XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libelf
SUBDIRS-y += x86_instruction_emulator

.PHONY: all clean distclean install
all clean distclean install: %: subdirs-%
