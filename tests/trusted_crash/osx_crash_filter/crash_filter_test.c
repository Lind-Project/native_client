/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <mach/exception.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <pthread.h>

#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/trusted/service_runtime/load_file.h"
#include "native_client/src/trusted/service_runtime/nacl_all_modules.h"
#include "native_client/src/trusted/service_runtime/nacl_app.h"
#include "native_client/src/trusted/service_runtime/osx/crash_filter.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"


/*
 * This function is provided by OS X's system libraries but the
 * headers lack a prototype for it.  This function is generated by
 * running MIG on /usr/include/mach/exc.defs.
 */
boolean_t exc_server(mach_msg_header_t *request, mach_msg_header_t *reply);

int g_expect_untrusted;


/*
 * exc_server() calls this function, and finds it via dlsym().  We
 * need to change the symbol's visibility in order to make it visible
 * to dlsym().  For details, see
 * http://code.google.com/p/google-breakpad/issues/detail?id=345
 */
__attribute__((visibility("default")))
kern_return_t catch_exception_raise(mach_port_t port,
                                    mach_port_t crashing_thread,
                                    mach_port_t task,
                                    exception_type_t exception_type,
                                    exception_data_t exception_code,
                                    mach_msg_type_number_t code_count) {
  int is_untrusted;

  UNREFERENCED_PARAMETER(port);
  UNREFERENCED_PARAMETER(exception_type);
  UNREFERENCED_PARAMETER(exception_code);
  UNREFERENCED_PARAMETER(code_count);

  CHECK(task == mach_task_self());
  fprintf(stderr, "Received a crash, as expected\n");
  is_untrusted = NaClMachThreadIsInUntrusted(crashing_thread);
  CHECK(is_untrusted == g_expect_untrusted);

  fprintf(stderr, "** intended_exit_status=0\n");
  exit(0);
}

void *ExceptionHandlerThread(void *thread_arg) {
  mach_port_t handler_port = (mach_port_t) (uintptr_t) thread_arg;

  while (1) {
    struct {
      mach_msg_header_t header;
      uint8_t data[256];
    } receive;
    mach_msg_header_t reply;
    kern_return_t rc;

    receive.header.msgh_local_port = handler_port;
    receive.header.msgh_size = sizeof(receive);
    rc = mach_msg(&receive.header,
                  MACH_RCV_MSG | MACH_RCV_LARGE, 0,
                  receive.header.msgh_size, handler_port,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    CHECK(rc == KERN_SUCCESS);
    CHECK(exc_server(&receive.header, &reply));
    exit(1);
  }

  return NULL;
}

void RegisterExceptionHandler(void) {
  mach_port_t task = mach_task_self();
  mach_port_t handler_port;
  kern_return_t rc;
  pthread_t tid;
  int err;

  /* Use the same mask as Breakpad. */
  exception_mask_t exception_mask =
    EXC_MASK_BAD_ACCESS |
    EXC_MASK_BAD_INSTRUCTION |
    EXC_MASK_ARITHMETIC |
    EXC_MASK_BREAKPOINT;

  rc = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &handler_port);
  CHECK(rc == KERN_SUCCESS);

  rc = mach_port_insert_right(task, handler_port, handler_port,
                              MACH_MSG_TYPE_MAKE_SEND);
  CHECK(rc == KERN_SUCCESS);

  err = pthread_create(&tid, NULL, ExceptionHandlerThread,
                       (void *) (uintptr_t) handler_port);
  CHECK(err == 0);
  err = pthread_detach(tid);
  CHECK(err == 0);

  rc = task_set_exception_ports(mach_task_self(), exception_mask,
                                handler_port, EXCEPTION_DEFAULT,
                                THREAD_STATE_NONE);
  CHECK(rc == KERN_SUCCESS);
}

int main(int argc, char **argv) {
  struct NaClApp app;

  if (argc == 2 && strcmp(argv[1], "early_trusted") == 0) {
    g_expect_untrusted = 0;
    RegisterExceptionHandler();
    /* Cause a crash. */
    *(volatile int *) 0 = 0;
  }

  if (argc != 3) {
    NaClLog(LOG_FATAL, "Expected 1 or 2 arguments\n");
  }

  if (strcmp(argv[1], "trusted") == 0) {
    g_expect_untrusted = 0;
  } else if (strcmp(argv[1], "untrusted") == 0) {
    g_expect_untrusted = 1;
  } else {
    NaClLog(LOG_FATAL, "1st argument (%s) not recognised\n", argv[1]);
  }

  NaClAllModulesInit();

  CHECK(NaClAppCtor(&app));
  CHECK(NaClAppLoadFileFromFilename(&app, argv[2]) == LOAD_OK);
  CHECK(NaClAppPrepareToLaunch(&app) == LOAD_OK);

  RegisterExceptionHandler();

  &app.tl_type = THREAD_LAUNCH_MAIN;

  CHECK(NaClCreateThread(NULL, &app, 0, NULL, NULL));
  NaClWaitForMainThreadToExit(&app);
  NaClLog(LOG_FATAL, "Did not expect the guest code to exit\n");
  return 1;
}
