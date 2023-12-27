/*
 * Copyright 2010 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can
 * be found in the LICENSE file.
 */

#include <stdio.h>
#include "native_client/src/shared/gio/gio_test_base.h"
#include "gtest/gtest.h"

#define EXPECT_RETCODE(_E_, _R_)                                 \
  EXPECT_EQ(_E_, _R_);

/* Uncomment and connect to above macro for debugging.
    if (0 > _R_) {                                               \
      perror("Bad return code");                                 \
    }
*/

char GioExpectedCharAt(char initial_char, int file_pos) {
  return static_cast<char>(initial_char + file_pos);
}

void GioInitTestMemFile(char* mem_buff, char initial_char, int in_size) {
  for (int i = 0; i < in_size; ++i)
    mem_buff[i] = GioExpectedCharAt(initial_char, i);
}

void GioReadTestWithOffset(struct Gio* my_file,
                           char initial_char) {
  char* out_buffer;
  int out_size = 16;
  ssize_t ret_code;

  out_buffer = reinterpret_cast<char*>(malloc(out_size));

  // mf_curpos = 0, 32 left, read 16
  ret_code = my_file->vtbl->Read(my_file, out_buffer, 16);
  EXPECT_RETCODE(16, ret_code);
  for (int i = 0; i < 16; ++i)
    EXPECT_EQ(GioExpectedCharAt(initial_char, i), out_buffer[i]);

  // mf_curpos = 16, 16 left, read 10
  ret_code = my_file->vtbl->Read(my_file, out_buffer, 10);
  EXPECT_RETCODE(10, ret_code);
  for (int i = 0; i < 10; ++i)
    EXPECT_EQ(GioExpectedCharAt(initial_char, i + 16), out_buffer[i]);
  // residual value after idx 10
  EXPECT_EQ(GioExpectedCharAt(initial_char, 10), out_buffer[10]);

  // mf_curpos = 26, 6 left, read 8
  ret_code = my_file->vtbl->Read(my_file, out_buffer, 8);
  EXPECT_RETCODE(6, ret_code);
  for (int i = 0; i < 6; ++i)
    EXPECT_EQ(GioExpectedCharAt(initial_char, i + 26), out_buffer[i]);
  // residual value after idx 6
  EXPECT_EQ(GioExpectedCharAt(initial_char, 16 + 6), out_buffer[6]);

  // mf_curpos = 32, 0 left, read 16
  ret_code = my_file->vtbl->Read(my_file, out_buffer, 16);
  EXPECT_EQ(0, ret_code);
  // Free the previously allocated memory for out_buffer
  free(out_buffer);
}

/** Should be given a scratch file that can be written to without worry. */
void GioWriteTest(struct Gio* my_file, bool fixed_length) {
    char* in_buffer = NULL; // Initialize in_buffer to NULL

    int in_size = 44;
    char initial_char = 'A';
    char out_char;
    ssize_t ret_code;

    // Allocate memory for in_buffer and populate it
    in_buffer = reinterpret_cast<char*>(malloc(in_size));
    if (in_buffer == NULL) {
        // Handle allocation failure
        // Example: printf("Memory allocation failed for in_buffer\n");
        return;
    }

    for (int i = 0; i < in_size; ++i)
        in_buffer[i] = GioExpectedCharAt(initial_char, i);

    // Write operation using in_buffer
    ret_code = my_file->vtbl->Write(my_file, in_buffer, in_size);
    // Perform other operations using in_buffer

    // Free the allocated memory for in_buffer
    free(in_buffer);

    // Reallocate memory for in_buffer if needed based on fixed_length condition
    if (fixed_length) {
        in_buffer = reinterpret_cast<char*>(malloc(in_size));
        if (in_buffer == NULL) {
            // Handle allocation failure
            // Example: printf("Memory allocation failed for in_buffer\n");
            return;
        }

        // Reinitialize in_buffer data if needed
        // Example: for (int i = 0; i < in_size; ++i) in_buffer[i] = ...
    
        // Perform subsequent operations using in_buffer if reallocated
        ret_code = my_file->vtbl->Write(my_file, in_buffer, 20);
        // Other operations...
        
        // Free the reallocated memory for in_buffer
        free(in_buffer);
    }
}

void GioSeekTestWithOffset(struct Gio* my_file,
                           char initial_char,
                           bool wrap_err) {
  char out_char;
  ssize_t ret_code;

  // mf_curpos = 0
  ret_code = my_file->vtbl->Seek(my_file, 15, SEEK_SET);
  EXPECT_RETCODE(15, ret_code);

  ret_code = my_file->vtbl->Read(my_file, &out_char, 1);
  EXPECT_RETCODE(1, ret_code);
  EXPECT_EQ(GioExpectedCharAt(initial_char, 15), out_char);

  // mf_curpos = 16
  ret_code = my_file->vtbl->Seek(my_file, 4, SEEK_CUR);
  EXPECT_RETCODE(20, ret_code);

  ret_code = my_file->vtbl->Read(my_file, &out_char, 1);
  EXPECT_RETCODE(1, ret_code);
  EXPECT_EQ(GioExpectedCharAt(initial_char, 20), out_char);

  // mf_curpos = 21
  ret_code = my_file->vtbl->Seek(my_file, -4, SEEK_CUR);
  EXPECT_RETCODE(17, ret_code);

  ret_code = my_file->vtbl->Read(my_file, &out_char, 1);
  EXPECT_RETCODE(1, ret_code);
  EXPECT_EQ(GioExpectedCharAt(initial_char, 17), out_char);

  // mf_curpos = 17
  ret_code = my_file->vtbl->Seek(my_file, -4, SEEK_END);
  EXPECT_RETCODE(28, ret_code);

  my_file->vtbl->Read(my_file, &out_char, 1);
  EXPECT_EQ(GioExpectedCharAt(initial_char, 28), out_char);


  // At this point we try to seek out of bounds in various ways.
  if (wrap_err) {
    const int BAD_SEEK_WHENCE = SEEK_END + 3;

    // mf_curpos = 29
    ret_code = my_file->vtbl->Seek(my_file, 4, SEEK_END);
    EXPECT_RETCODE(-1, ret_code);

    my_file->vtbl->Read(my_file, &out_char, 1);
    EXPECT_EQ(GioExpectedCharAt(initial_char, 29), out_char);

    // mf_curpos = 30
    ret_code = my_file->vtbl->Seek(my_file, 4, BAD_SEEK_WHENCE);
    EXPECT_RETCODE(-1, ret_code);

    my_file->vtbl->Read(my_file, &out_char, 1);
    EXPECT_EQ(GioExpectedCharAt(initial_char, 30), out_char);

    // mf_curpos = 31
    ret_code = my_file->vtbl->Seek(my_file, -5, SEEK_SET);
    EXPECT_RETCODE(-1, ret_code);

    my_file->vtbl->Read(my_file, &out_char, 1);
    EXPECT_EQ(GioExpectedCharAt(initial_char, 31), out_char);
  } else {
    // Not testing seek past end and then READING.

    // mf_curpos = 29
    ret_code = my_file->vtbl->Seek(my_file, -5, SEEK_SET);
    EXPECT_RETCODE(-1, ret_code);

    /* Different behavior on Windows vs Posix.
       It appears that file_pos after a bad seek is undefined.
       TODO(jvoung): Once gio library makes seek behavior standard,
       we can re-enable this test. See:
       http://code.google.com/p/nativeclient/issues/detail?id=850
    my_file->vtbl->Read(my_file, &out_char, 1);
    EXPECT_EQ(GioExpectedCharAt(initial_char, 29), out_char);
    */
  }
}

void GioCloseTest(struct Gio* my_file) {
  int ret_code;
  ret_code = my_file->vtbl->Close(my_file);
  EXPECT_RETCODE(0, ret_code);
  my_file->vtbl->Dtor(my_file);
}
