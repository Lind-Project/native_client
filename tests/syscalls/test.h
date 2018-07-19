/*
 * Copyright 2010 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can
 * be found in the LICENSE file.
 */

#ifndef TESTS_SYSCALLS_TEST_H_
#define TESTS_SYSCALLS_TEST_H_

//  Some simple functions to help with testing.  See below for some macros that
//  make for a very simple test framework.

namespace test {
  // Print a failure message and return false, including a file name and line
  // number in the message that is printed.
  bool Failed(const char *testname,
              const char *msg,
              const char* file,
              int line);
  // Print a failure message and return false.
  bool Failed(const char *testname, const char *msg);


  // Call this to print a message and return true.  Note that this message
  // should not contain data specific to an instance of a test run, so that
  // golden output can be used if desired.
  bool Passed(const char *testname, const char *msg);
}  // namespace test

#define START_TEST(TESTNAME)                               \
  int _fail_count = 0;                                     \
  const char* const _test_name = TESTNAME;

#define EXPECT(COND)                                       \
  if (COND) {                                              \
    ::test::Passed(_test_name, #COND);                     \
  } else {                                                 \
    ::test::Failed(_test_name, #COND, __FILE__, __LINE__); \
    ++_fail_count;                                         \
  }

#define END_TEST() do { return _fail_count; } while (0)

#endif  // NATIVE_CLIENT_TESTS_SYSCALLS_TEST_H_

// vi:ft=cpp:
