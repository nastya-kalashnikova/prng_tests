# /usr/share/doc/testu01-doc/examples/Makefile
#
# Ad hoc Makefile for building and playing with the sample sources
# distributed within the debian package testu01-doc.
#
# Recommended usage:
#  create a dedicated folder somewhere in your HOME directory;
#  link all the files in /usr/share/doc/testu01-doc/examples in the dedicated folder;
#  launch this Makefile in the dedicated folder:
#  $ make ;
#  for a basic cleanup, consider the clean target:
#  $ make clean ;
#  for an entire cleanup, the maintainer-clean target:
#  $ make maintainer-clean
#  for other targets, just read the Makefile.
#
# written for Debian by Jerome Benoit <calculus@rezozer.net>
# on behalf of the Debian Science Team
# copyright: 2015-2017 Jerome Benoit <calculus@rezozer.net>
# distributed under the terms and conditions of GPL version 3 or later
#

SHELL = /bin/bash
#CC = gcc-12 # Flag for implicit rules
#CFLAGS = -Wall -O3 -g0 

default: all

#PROGRAMS = AKalashnikovaChaCha20
#PROGRAMS = AKalashnikovaGaloisLeftLFSR
#PROGRAMS = AKalashnikovaGaloisRightLFSR

RESULTFILES = \
	$(addsuffix .res,$(PROGRAMS))

DISTCLEANFILES = \
	$(PDFSCRAPFILES)

LDLIBS = -ltestu01

ex3: ex3.c my16807.c my16807.h
	$(CC) $(CFLAGS) $(filter-out %.h,$^) $(LDLIBS) -ltestu01mylib -o $@

ex7: ex7.c mrg32k3a.c xorshift.c
AKalashnikovaGaloisLeftLFSR: AKalashnikovaGaloisLeftLFSR.c galoisLeftLFSR.c
AKalashnikovaGaloisRightLFSR: AKalashnikovaGaloisRightLFSR.c galoisRightLFSR.c
AKalashnikovaChaCha20: AKalashnikovaChaCha20.c chacha20.c

all: build check

build: $(PROGRAMS)

check: $(RESULTFILES)

mostlyclean:
	$(RM) $(COMPOSEDIR)/*
	test ! -d $(COMPOSEDIR) || $(RMDIR) $(COMPOSEDIR)

checkclean:
	$(RM) $(RESULTFILES)

clean: mostlyclean checkclean
	$(RM) $(PROGRAMS)

distclean: clean
	$(RM) $(DISTCLEANFILES)

%.res : %
	./$< | tee $@
#%.res : %
#	./$< > $@

COMPOSEDIR ?= $(TMPDIR)/mk/$(subst /,%,$(realpath $(firstword $(MAKEFILE_LIST))))%compose

TMPDIR ?= /tmp

MV ?= /bin/mv -f
MKDIR_P ?= /bin/mkdir -p
RMDIR ?= /bin/rmdir
