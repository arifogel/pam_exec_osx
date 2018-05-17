dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(pam_exec_osx, 0.1)
AC_PROG_CC

AC_CANONICAL_SYSTEM

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/pam_exec_osx_config.h])
AH_TOP([#include <syslog.h>
])
AH_TEMPLATE([PAM_EXEC_OSX_LOG_LEVEL],
            [Default log level as in 'syslog.h'.
            One of: LOG_EMERG, LOG_ALERT, LOG_CRIT,
            LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG])
AC_ARG_ENABLE([log-level],
            [AS_HELP_STRING([--enable-log-level=level], [one of
             LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
             LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG])],
              [AC_DEFINE_UNQUOTED([PAM_EXEC_OSX_LOG_LEVEL], [${enable_log_level}])]
             ,[AC_DEFINE([PAM_EXEC_OSX_LOG_LEVEL], [(LOG_INFO)])])

dnl Initialize automake
AM_INIT_AUTOMAKE

dnl this allows us specify individual linking flags for each target
AM_PROG_CC_C_O 

dnl Initialize Libtool
LT_INIT

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

