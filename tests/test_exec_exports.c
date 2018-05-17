#include <dlfcn.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void* pam_access_osx;

int main(void) {
  // Load module
  pam_access_osx = dlopen("../pam_access_osx/.libs/pam_access_osx.so", RTLD_NOW | RTLD_GLOBAL | RTLD_FIRST);
  if (pam_access_osx == NULL) {
    fprintf(stderr, "Could not open pam_access_osx module: %s", dlerror());
    exit(1);
  }

  // Load the pam_sm_authenticate function
  int
  (*pam_sm_authenticate)(
    pam_handle_t*,
    int,
    int,
    const char**) =
      (int(*)(pam_handle_t*, int, int, const char**))
      dlsym(pam_access_osx, "pam_sm_authenticate");
  if (pam_sm_authenticate == NULL) {
    fprintf(stderr, "Failed to load pam_sm_authenticate function: %s", dlerror());
    exit(1);
  }

  exit(0);
}

