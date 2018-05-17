AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS=-I m4

### Module and test library

pam_exec_osxdir = $(libdir)/security

pam_exec_osx_LTLIBRARIES = pam_exec_osx.la

MODULE_SRC = src/pam_exec_osx.h src/pam_exec_osx.c

pam_exec_osx_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -export-dynamic -module -shared -export-symbols-regex "pam_sm_authenticate"
pam_exec_osx_la_LIBADD = -lpam
pam_exec_osx_la_SOURCES = $(MODULE_SRC)

check_LTLIBRARIES = libpam_exec_osx_test.la

libpam_exec_osx_test_la_SOURCES = $(MODULE_SRC)
libpam_exec_osx_test_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -rpath $(abs_top_builddir)

### Tests
TEST_NAMES = \
	test_exec_exports


TESTS = $(TEST_NAMES)

check_PROGRAMS = $(TEST_NAMES)

TEST_LIB = $(top_srcdir)/libpam_exec_osx_test.la

### Exports test
test_exec_exports_CPPFLAGS = -I$(top_srcdir)/src
test_exec_exports_SOURCES = tests/test_exec_exports.c

### Other tests

# Test template
#test_exec_<CHANGEME>_CPPFLAGS = -I$(top_srcdir)/src
#test_exec_<CHANGEME>_LDADD = $(TEST_LIB)
#test_exec_<CHANGEME>_SOURCES = tests/test_exec_<CHANGEME>.c

