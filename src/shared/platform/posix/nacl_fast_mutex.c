/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_host_desc.h"
#include "native_client/src/shared/platform/posix/nacl_fast_mutex.h"

int NaClFastMutexCtor(struct NaClFastMutex *flp) {
  if (0 != pthread_mutex_init(&flp->mu, (pthread_mutexattr_t *) NULL)) {
    return 0;
  }
  return 1;
}

void NaClFastMutexDtor(struct NaClFastMutex *flp) {
  pthread_mutex_destroy(&flp->mu);
}

void NaClFastMutexLock(struct NaClFastMutex *flp) {
  CHECK(0 == pthread_mutex_lock(&flp->mu));
}

int NaClFastMutexTryLock(struct NaClFastMutex *flp) {
  return NaClXlateErrno(pthread_mutex_trylock(&flp->mu));
}

void NaClFastMutexUnlock(struct NaClFastMutex *flp) {
  CHECK(0 == pthread_mutex_unlock(&flp->mu));
}

int NaClFastRWLockCtor(struct NaClFastRWLock *flp) {
  if (0 != pthread_rwlock_init(&flp->mu, (pthread_rwlockattr_t *) NULL)) {
    return 0;
  }
  return 1;
}

void NaClFastRWLockDtor(struct NaClFastRWLock *flp) {
  pthread_rwlock_destroy(&flp->mu);
}

void NaClFastMutexRWLockRd(struct NaClFastRWLock *flp) {
  CHECK(0 == pthread_rwlock_rdlock(&flp->mu));
}

void NaClFastMutexRWLockWr(struct NaClFastRWLock *flp) {
  CHECK(0 == pthread_rwlock_wrlock(&flp->mu));
}

int NaClFastMutexTryRWLockRd(struct NaClFastRWLock *flp) {
  return NaClXlateErrno(pthread_rwlock_rdlock(&flp->mu));
}

int NaClFastMutexTryRWLockWr(struct NaClFastRWLock *flp) {
  return NaClXlateErrno(pthread_rwlock_wrlock(&flp->mu));
}

void NaClFastRWLockUnlock(struct NaClFastRWLock *flp) {
  CHECK(0 == pthread_rwlock_unlock(&flp->mu));
}
