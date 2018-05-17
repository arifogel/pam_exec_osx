#ifndef __PAM_EXEC_OSX_H__
#define __PAM_EXEC_OSX_H__

#include <security/pam_appl.h>
#include <sys/types.h>
#include <unistd.h>

#include "pam_exec_osx_config.h"

#define PAM_EXEC_OSX_CHILD_DENY (1)
#define PAM_EXEC_OSX_CHILD_ERR (-1)
#define PAM_EXEC_OSX_CHILD_PERMIT (0)

#define PAM_EXEC_OSX_IDENT ("pam_exec_osx")

#define PAM_EXEC_OSX_MODULE_ENTRY ("pam_exec_osx")

#define PAM_EXEC_OSX_ENV_USER ("PAM_EXEC_OSX_USER")
#define PAM_EXEC_OSX_ENV_RHOST ("PAM_EXEC_OSX_RHOST")

/**
 * Child process entry point in which command specified by argc and argv executes. This command is responsible
 * for authenticating, and runs in an environment in which variables PAM_EXEC_OSX_USER and PAM_EXEC_OSX_RHOST are
 * with pam_user and pam_rhost respectively.
 * Exits with:
 * - PAM_EXEC_OSX_CHILD_PERMIT, if command successfully authenticates pam
 */
void
pam_exec_osx_child(
  int argc,
  const char** argv,
  const char* pam_rhost,
  const char* pam_user);

/**
 *  Populates pam_user and pam_rhost via pamh.
 */
int
pam_exec_osx_init_pam_info(
  pam_handle_t* pamh,
  const char** pam_rhost,
  const char** pam_user);

/**
 * Parent process continuation point after forking child with PID child_pid.
 * Returns:
 * - PAM_AUTH_ERR if child process exits with PAM_EXEC_OSX_CHILD_DENY or PAM_EXEC_OSX_CHILD
 * - PAM_SUCESS if child process exits with PAM_EXEC_OSX_CHILD_PERMIT
 */
int
pam_exec_osx_parent(
  pid_t child_pid,
  const char* pam_rhost,
  const char* pam_user);

/**
 * Write format string to syslog facility LOG_AUTH with specified priority.
 */
void
pam_exec_osx_syslog(
  int priority,
  const char* format,
  ...);

#endif /*__PAM_EXEC_OSX_H__*/
