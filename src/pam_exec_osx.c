#include <inttypes.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "pam_exec_osx.h"

void
pam_exec_osx_child(
  int argc,
  const char** argv,
  const char* pam_rhost,
  const char* pam_user) {
  if (setenv(PAM_EXEC_OSX_ENV_RHOST, pam_rhost, 1) < 0) {
    pam_exec_osx_syslog(LOG_ERR, "Error adding pam_rhost to environment: %s\n", strerror(errno));
    exit(PAM_EXEC_OSX_CHILD_ERR);
  }
  if (setenv(PAM_EXEC_OSX_ENV_USER, pam_user, 1) < 0) {
    pam_exec_osx_syslog(LOG_ERR, "Error adding pam_user to environment: %s\n", strerror(errno));
    exit(PAM_EXEC_OSX_CHILD_ERR);
  }
  if (argc == 0) {
    pam_exec_osx_syslog(LOG_ERR, "No command specified!\n");
    exit(PAM_EXEC_OSX_CHILD_ERR);
  }

  int i;
  for (i = 0; i < argc && argv[i] != NULL; i++) {
    pam_exec_osx_syslog((LOG_DEBUG), "argv[%d] = %s\n", i, argv[i]);
  }

  /* execute the process */
  execv(argv[0], (char * const *) argv);

  /* Only reach here if execv call fails */
  pam_exec_osx_syslog(LOG_ERR, "Error executing subprocess: %s\n", strerror(errno));
  exit(PAM_EXEC_OSX_CHILD_ERR);
}

int
pam_exec_osx_init_pam_info(
  pam_handle_t* pamh,
  const char** pam_rhost,
  const char** pam_user) {
  // Get PAM_RHOST
  if (pam_get_item(pamh, PAM_RHOST, (const void**) pam_rhost) != PAM_SUCCESS) {
    pam_exec_osx_syslog(LOG_ERR, "Could not retrieve PAM_RHOST\n");
    return (PAM_AUTH_ERR);
  }
  pam_exec_osx_syslog(LOG_DEBUG, "PAM_RHOST: %s\n", *pam_rhost);

  // Get PAM user
  if (pam_get_user(pamh, pam_user, NULL) != PAM_SUCCESS || (pam_user == NULL)) {
    pam_exec_osx_syslog(LOG_ERR, "Could not retrieve PAM user\n");
    return (PAM_AUTH_ERR);
  }
  pam_exec_osx_syslog(LOG_DEBUG, "PAM user: %s\n", *pam_user);

  return (PAM_SUCCESS);
}

int
pam_exec_osx_parent(
  pid_t child_pid,
  const char* pam_rhost,
  const char* pam_user) {
  pam_exec_osx_syslog((LOG_DEBUG), "Forked child with PID: %" PRIdMAX "\n", (intmax_t) child_pid);
  int status;
  pid_t result = waitpid(child_pid, &status, 0);
  if (result < 0) {
    pam_exec_osx_syslog(
      (LOG_ERR),
      "Error waiting for child process to terminate: %s\n",
      strerror(errno));
    return (PAM_AUTH_ERR);
  }

  pam_exec_osx_syslog(
    (LOG_DEBUG),
    "Finished waiting for child process with PID %" PRIdMAX "\n",
    (intmax_t) child_pid);
  if (!WIFEXITED(status)) {
    pam_exec_osx_syslog(
      (LOG_ERR),
      "Child process with PID %" PRIdMAX " did not exit!\n",
      (intmax_t) child_pid);
    return (PAM_AUTH_ERR);
  }
  int exit_status = WEXITSTATUS(status);
  pam_exec_osx_syslog(
    (LOG_DEBUG),
    "Child process with PID %" PRIdMAX " exited with error code: %d\n",
    (intmax_t) child_pid,
    exit_status);
  if (exit_status == PAM_EXEC_OSX_CHILD_ERR) {
    pam_exec_osx_syslog(LOG_ERR, "Child process exited abormally\n");
    return (PAM_AUTH_ERR);
  } else if (exit_status == PAM_EXEC_OSX_CHILD_DENY) {
    pam_exec_osx_syslog(
      (LOG_INFO),
      "AUTHENTICATION FAILED - USER=%s RHOST=%s\n",
      pam_user,
      pam_rhost);
    return (PAM_PERM_DENIED);
  }
  pam_exec_osx_syslog(
    (LOG_INFO),
    "AUTHENTICATION SUCCEEDED - USER=%s  RHOST=%s\n",
    pam_user,
    pam_rhost);
  return (PAM_SUCCESS);
}

void
pam_exec_osx_syslog(
  int priority,
  const char* format,
  ...) {
  if (priority > PAM_EXEC_OSX_LOG_LEVEL) {
    return;
  }
  va_list args;
  va_start(args, format);
  openlog(PAM_EXEC_OSX_IDENT, 0, LOG_AUTH);
  vsyslog(priority, format, args);
  closelog();
}

PAM_EXTERN
int
pam_sm_authenticate(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  const char* pam_user = NULL;
  const char* pam_rhost = NULL;
  if (pam_exec_osx_init_pam_info(pamh, &pam_rhost, &pam_user) != 0) {
    pam_exec_osx_syslog(LOG_ERR, "Error retrieving PAM variables\n");
    return (PAM_AUTH_ERR);
  }
  pid_t pid = fork();
  if (pid < 0) {
    pam_exec_osx_syslog(LOG_ERR, "Failed to fork child process\n");
    return (PAM_AUTH_ERR);
  } else if (pid == 0) {
    pam_exec_osx_child(argc, argv, pam_rhost, pam_user);
    // Should not get here
    return (PAM_AUTH_ERR);
  } else {
    return pam_exec_osx_parent(pid, pam_rhost, pam_user);
  }
}

PAM_EXTERN
int
pam_sm_acct_mgmt(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_chauthtok(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_close_session(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_open_session(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_EXTERN
int
pam_sm_setcred(
  pam_handle_t* pamh,
  int flags,
  int argc,
  const char** argv) {
  return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY(PAM_EXEC_OSX_MODULE_ENTRY);

