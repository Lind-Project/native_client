/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <inttypes.h>
#include <stdio.h>
#include <time.h>

#define DEFERRED_STRINGIFY(symbol) #symbol
#define SHOW(symbol)                                  \
  do {                                                \
    printf("Current definition for %s is \"%s\".\n",  \
           #symbol, DEFERRED_STRINGIFY(symbol));      \
  } while (0)

void ShowCurrentDefinitions(void) {
  SHOW(CLOCK_REALTIME);
  SHOW(CLOCK_MONOTONIC);
  SHOW(CLOCK_PROCESS_CPUTIME_ID);
  SHOW(CLOCK_THREAD_CPUTIME_ID);
}

struct timespec;

/*
 * Basic functionality test: the syscalls are present.
 */
int TimeTest(int (*func)(clockid_t clk_id, struct timespec *ts),
             clockid_t clk_id,
             char const *error_string,
             char const *success_name) {
  struct timespec       ts;

  if (0 != (*func)(clk_id, &ts)) {
    fprintf(stderr, "%s\n", error_string);
    return 1;
  }
  printf("%30s: %lld.%09lu\n", success_name,
         (int64_t) ts.tv_sec, (unsigned long) ts.tv_nsec);
  return 0;
}

int main(void) {
  int errs = 0;

  ShowCurrentDefinitions();

  errs += TimeTest(clock_getres, CLOCK_REALTIME,
                   "clock_getres on realtime clock failed",
                   "Realtime clock resolution");
  errs += TimeTest(clock_getres, CLOCK_MONOTONIC,
                   "clock_getres on monotonic clock failed",
                   "Monotonic clock resolution");
  errs += TimeTest(clock_gettime, CLOCK_REALTIME,
                   "clock_gettime on realtime clock failed",
                   "Realtime clock value");
  errs += TimeTest(clock_gettime, CLOCK_MONOTONIC,
                   "clock_gettime on monotonic clock failed",
                   "Monotonic clock value");
  return errs;
}
