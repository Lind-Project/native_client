/*
 * lind_api.c
 *
 *  Created on: Jun 27, 2013
 *      Author: sji
 */


#include <Python.h>

#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>

#include "native_client/src/shared/platform/nacl_sync_checked.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/shared/platform/nacl_host_desc.h"

#include "native_client/src/include/portability.h"

#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_copy.h"
#include "native_client/src/trusted/service_runtime/lind_syscalls.h"


#define GOTO_ERROR_IF_NULL(x) if(!(x)) {goto error;}

extern PyObject* context;

#define MAX_INARGS 16
#define MAX_OUTARGS 16

typedef enum _LindArgType {AT_INT, AT_STRING, AT_STRING_OPTIONAL, AT_DATA, AT_DATA_OPTIONAL} LindArgType;

struct NaClDescVtbl const kNaClDescIoDescVtbl;

typedef struct _LindArg
{
    LindArgType type;
    uint64_t ptr;
    uint64_t len;
} LindArg;

static PyObject* CallPythonFunc(PyObject* context, const char* func, PyObject* args)
{
    PyObject* func_obj = NULL;
    PyObject* result = NULL;
    func_obj = PyDict_GetItemString(context, func);
    GOTO_ERROR_IF_NULL(func_obj);
    GOTO_ERROR_IF_NULL(args);
    result = PyObject_CallObject(func_obj, args);
    GOTO_ERROR_IF_NULL(result);
    return result;
error:
    PyErr_Print();
    Py_XDECREF(func_obj);
    return 0;
}

static int ParseResponse(PyObject* response, int* isError, int* code, char** dataOrMessage, int* len)
{
    int retval = 0;
    PyObject* attrIsError = NULL;
    PyObject* attrCode = NULL;
    PyObject* attrDataOrMessage = NULL;

    NaClLog(3, "Entered ParseResponse\n");

    attrIsError = PyObject_GetAttrString(response, "is_error");
    GOTO_ERROR_IF_NULL(attrIsError);

    attrCode = PyObject_GetAttrString(response, "return_code");
    GOTO_ERROR_IF_NULL(attrCode);

    *dataOrMessage = NULL;
    *len = 0;

    if(attrIsError == Py_True) {
        *isError = 1;
        attrDataOrMessage = PyObject_GetAttrString(response, "message");
        GOTO_ERROR_IF_NULL(attrDataOrMessage);
    } else {
        *isError = 0;
        attrDataOrMessage = PyObject_GetAttrString(response, "data");
    }

    *code = PyInt_AsLong(attrCode);
    if(PyErr_Occurred()) {
        goto error;
    }

    if(attrDataOrMessage) {
        *dataOrMessage = PyString_AsString(attrDataOrMessage);
        if(PyErr_Occurred()) {
            goto error;
        }
        *len = (int)PyString_Size(attrDataOrMessage);
        if(PyErr_Occurred()) {
            goto error;
        }
    }
    NaClLog(3, "ParseResponse isError=%d, code=%d, len=%d\n", *isError, *code, *len);
    if(*isError) {
        NaClLog(3, "Error message: %s\n", *dataOrMessage);
    }
    retval = 1;
    goto cleanup;
error:
    NaClLog(LOG_ERROR, "ParseResponse Python error\n");
    PyErr_Print();
cleanup:
    Py_XDECREF(attrIsError);
    Py_XDECREF(attrCode);
    Py_XDECREF(attrDataOrMessage);
    return retval;
}

void DumpArg(const LindArg *arg)
{
    printf("%"NACL_PRId64":%"NACL_PRIu64":%"NACL_PRIu64"\n", (uint64_t)arg->type, arg->ptr, arg->len);
}

//If error occurs, any data malloc'ed in Preprocess must be freed before return
//otherwise, they must be freed in Cleanup
typedef int(*PreprocessType)(struct NaClApp*, uint32_t, LindArg*, void**);
typedef int(*PostprocessType)(struct NaClApp*, int, int*, char*, int, void*);
typedef int(*CleanupType)(struct NaClApp*, uint32_t, LindArg*, void*);

typedef struct _StubType {PreprocessType pre; PostprocessType post; CleanupType clean;} StubType;


int LindSelectCleanup(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void* xchangedata)
{
    UNREFERENCED_PARAMETER(nap);
    UNREFERENCED_PARAMETER(inNum);
    NaClLog(3, "Entering LindSelectCleanup\n");
    if(inArgs[1].ptr) {
        free((void*)inArgs[1].ptr);
    }
    if(inArgs[2].ptr) {
        free((void*)inArgs[2].ptr);
    }
    if(inArgs[3].ptr) {
        free((void*)inArgs[3].ptr);
    }
    free(xchangedata);
    NaClLog(3, "Exiting LindSelectCleanup\n");
    return 0;
}

int LindSelectPreprocess(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void** xchangedata)
{
    struct NaClDesc *ndp = NULL;
    int hfd;
    int retval = 0;
    int* mapdata;
    fd_set rs;
    fd_set ws;
    fd_set es;
    int64_t max_fd;
    int64_t max_hfd = -1;
    NaClLog(3, "Entered LindSelectPreprocess inNum=%8u\n", inNum);
    max_fd = *(int64_t*)&inArgs[0].ptr;
    if(inArgs[1].ptr) {
        rs = *(fd_set*)inArgs[1].ptr;
        inArgs[1].ptr=(uintptr_t)malloc(sizeof(fd_set));
        if (NULL == (void*)inArgs[1].ptr) {
            retval = -NACL_ABI_ENOMEM;
            goto finish;
        }
        FD_ZERO((fd_set*)inArgs[1].ptr);
    }
    if(inArgs[2].ptr) {
        ws = *(fd_set*)inArgs[2].ptr;
        inArgs[2].ptr=(uintptr_t)malloc(sizeof(fd_set));
        if (NULL == (void*)inArgs[2].ptr) {
            retval = -NACL_ABI_ENOMEM;
            goto cleanup_rs;
        }
        FD_ZERO((fd_set*)inArgs[2].ptr);
    }
    if(inArgs[3].ptr) {
        es = *(fd_set*)inArgs[3].ptr;
        inArgs[3].ptr=(uintptr_t)malloc(sizeof(fd_set));
        if (NULL == (void*)inArgs[3].ptr) {
            retval = -NACL_ABI_ENOMEM;
            goto cleanup_ws;
        }
        FD_ZERO((fd_set*)inArgs[3].ptr);
    }
    *xchangedata = malloc(sizeof(int)*(FD_SETSIZE+1));
    if (NULL == *xchangedata) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup_es;
    }
    memset(*xchangedata, 0xFF, sizeof(int)*FD_SETSIZE);
    mapdata = &((int*)(*xchangedata))[1];
    NaClFastMutexLock(&nap->desc_mu);
    for(int i=0; i<max_fd; ++i) {
        ndp = NULL;
        if((inArgs[1].ptr && FD_ISSET(i, &rs)) ||
                (inArgs[2].ptr && FD_ISSET(i, &ws)) ||
                (inArgs[3].ptr && FD_ISSET(i, &es))) {
            ndp = NaClGetDescMu(nap, i);
            if(ndp && ndp->base.vtbl == (struct NaClRefCountVtbl const *)&kNaClDescIoDescVtbl) {
                hfd = ((struct NaClDescIoDesc*)ndp)->hd->d;
                if(hfd<FD_SETSIZE) {
                    if(hfd > max_hfd) {
                        max_hfd = hfd;
                    }
                    mapdata[hfd]=i;
                } else {
                    NaClLog(LOG_ERROR, "Host desc too large: %d->%d\n", i, hfd);
                    retval = -NACL_ABI_EINVAL;
                    goto cleanup_xdata;
                }
            } else {
                NaClLog(LOG_ERROR, "Invalid NaCl desc: %d\n", i);
                retval = -NACL_ABI_EINVAL;
                goto cleanup_xdata;
            }
            if(inArgs[1].ptr && FD_ISSET(i, &rs)) {
                NaClLog(3, "%d in RS with host desc %d\n", i, hfd);
                FD_SET(hfd, (fd_set*)inArgs[1].ptr);
            }
            if(inArgs[2].ptr && FD_ISSET(i, &ws)) {
                NaClLog(3, "%d in WS with host desc %d\n", i, hfd);
                FD_SET(hfd, (fd_set*)inArgs[2].ptr);
            }
            if(inArgs[3].ptr && FD_ISSET(i, &es)) {
                NaClLog(3, "%d in ES with host desc %d\n", i, hfd);
                FD_SET(hfd, (fd_set*)inArgs[3].ptr);
            }
        }
    }
    *(int64_t*)&inArgs[0].ptr = max_hfd+1;
    ((int*)(*xchangedata))[0] = max_hfd+1;
    NaClLog(3, "max_fd is set to %"NACL_PRId64" was %"NACL_PRId64"\n", max_fd, (int64_t)inArgs[0].ptr);
    NaClFastMutexUnlock(&nap->desc_mu);
    goto finish;
cleanup_xdata:
    free(*xchangedata);
cleanup_es:
    if(inArgs[3].ptr) {
        free((void*)inArgs[3].ptr);
    }
cleanup_ws:
    if(inArgs[2].ptr) {
        free((void*)inArgs[2].ptr);
    }
cleanup_rs:
    if(inArgs[1].ptr) {
        free((void*)inArgs[1].ptr);
    }
finish:
    NaClLog(3, "Exiting LindSelectPreprocess\n");
    return retval;
}

int LindSelectPostprocess(struct NaClApp *nap, int iserror, int* code, char* data, int len, void* xchangedata)
{
    int* mapdata;
    int max_hfd;
    int retval = 0;
    fd_set rs;
    fd_set ws;
    fd_set es;
    UNREFERENCED_PARAMETER(nap);
    UNREFERENCED_PARAMETER(iserror);
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(len);
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    max_hfd = ((int*)xchangedata)[0];
    mapdata = &((int*)xchangedata)[1];
    for(int i=0; i<max_hfd; ++i) {
        if(FD_ISSET(i, &((struct select_results*)data)->r)) {
            if(-1 != mapdata[i]) {
                NaClLog(3, "%d in RS with nacl desc %d\n", i, mapdata[i]);
                FD_SET(mapdata[i], &rs);
            } else {
                NaClLog(3, "%d in RS not valid, ignored\n", i);
            }
        }
        if(FD_ISSET(i, &((struct select_results*)data)->w)) {
            if(-1 != mapdata[i]) {
                NaClLog(3, "%d in WS with nacl desc %d\n", i, mapdata[i]);
                FD_SET(mapdata[i], &ws);
            } else {
                NaClLog(3, "%d in WS not valid, ignored\n", i);
            }
        }
        if(FD_ISSET(i, &((struct select_results*)data)->e)) {
            if(-1 != mapdata[i]) {
                NaClLog(3, "%d in ES with nacl desc %d\n", i, mapdata[i]);
                FD_SET(mapdata[i], &es);
            } else {
                NaClLog(3, "%d in ES not valid, ignored\n", i);
            }
        }
    }
    ((struct select_results*)data)->r = rs;
    ((struct select_results*)data)->w = ws;
    ((struct select_results*)data)->e = es;
    return retval;
}

static int NaClHostDescCtor(struct NaClHostDesc  *d,
                            int fd,
                            int flags) {
  d->d = fd;
  d->flags = flags;
  NaClLog(3, "NaClHostDescCtor: success.\n");
  return 0;
}

#define CONVERT_NACL_DESC_TO_LIND(x) \
    int retval = 0; \
    struct NaClDesc * ndp; \
    UNREFERENCED_PARAMETER(inNum); \
    UNREFERENCED_PARAMETER(xchangedata); \
    NaClFastMutexLock(&nap->desc_mu); \
    ndp = NaClGetDescMu(nap, (int)(*(int64_t*)&inArgs[(x)].ptr)); \
    NaClFastMutexUnlock(&nap->desc_mu); \
    if(!ndp || ndp->base.vtbl != (struct NaClRefCountVtbl const *)&kNaClDescIoDescVtbl) { \
        retval = -NACL_ABI_EINVAL; \
        goto cleanup; \
    } \
    *(int64_t*)&inArgs[(x)].ptr = ((struct NaClDescIoDesc *)ndp)->hd->d; \
cleanup: \
    return retval

#define ALLOC_RET_DESC() \
    int retval = 0; \
    UNREFERENCED_PARAMETER(nap); \
    UNREFERENCED_PARAMETER(inNum); \
    UNREFERENCED_PARAMETER(inArgs); \
    *xchangedata = malloc(sizeof(struct NaClHostDesc)); \
    if (NULL == *xchangedata) { \
      retval = -NACL_ABI_ENOMEM; \
      goto cleanup; \
    } \
cleanup: \
    return retval

#define CONVERT_NACL_DESC_TO_LIND_AND_ALLOC_RET_DESC(x) \
    int retval = 0; \
    struct NaClDesc* ndp; \
    UNREFERENCED_PARAMETER(inNum); \
    *xchangedata = malloc(sizeof(struct NaClHostDesc)); \
    if (NULL == *xchangedata) { \
      retval = -NACL_ABI_ENOMEM; \
      goto cleanup; \
    } \
    NaClFastMutexLock(&nap->desc_mu); \
    ndp = NaClGetDescMu(nap, (int)(*(int64_t*)&inArgs[(x)].ptr)); \
    NaClFastMutexUnlock(&nap->desc_mu); \
    if(!ndp || ndp->base.vtbl != (struct NaClRefCountVtbl const *)&kNaClDescIoDescVtbl) { \
        retval = -NACL_ABI_EINVAL; \
        goto cleanup; \
    } \
    *(int64_t*)&inArgs[(x)].ptr = ((struct NaClDescIoDesc *)ndp)->hd->d; \
cleanup: \
    return retval

#define BUILD_AND_RETURN_NACL_DESC() \
    int retval = 0; \
    struct NaClHostDesc  *hd; \
    UNREFERENCED_PARAMETER(iserror); \
    UNREFERENCED_PARAMETER(data); \
    UNREFERENCED_PARAMETER(len); \
    hd = (struct NaClHostDesc*)xchangedata; \
    NaClHostDescCtor(hd, *code, NACL_ABI_O_RDWR); \
    *code = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd))); \
    return retval

int LindSocketPreprocess(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void** xchangedata)
{
    ALLOC_RET_DESC();
}

int LindSocketPostprocess(struct NaClApp *nap, int iserror, int* code, char* data, int len, void* xchangedata)
{
    BUILD_AND_RETURN_NACL_DESC();
}

int LindAcceptPreprocess(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void** xchangedata)
{
    CONVERT_NACL_DESC_TO_LIND_AND_ALLOC_RET_DESC(0);
}

int LindAcceptPostprocess(struct NaClApp *nap, int iserror, int* code, char* data, int len, void* xchangedata)
{
    BUILD_AND_RETURN_NACL_DESC();
}

int LindCommonPreprocess(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void** xchangedata)
{
    CONVERT_NACL_DESC_TO_LIND(0);
}

int LindSocketPairPreprocess(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void** xchangedata)
{
    int retval = 0;
    UNREFERENCED_PARAMETER(nap);
    UNREFERENCED_PARAMETER(inNum);
    UNREFERENCED_PARAMETER(inArgs);
    *xchangedata = malloc(sizeof(struct NaClHostDesc)*2);
    if (NULL == *xchangedata) {
      retval = -NACL_ABI_ENOMEM;
      goto cleanup;
    }
cleanup:
    return retval;
}

int LindSocketPairPostprocess(struct NaClApp *nap, int iserror, int* code, char* data, int len, void* xchangedata)
{
    int retval = 0;
    struct NaClHostDesc  *hd;
    int lind_fd;
    UNREFERENCED_PARAMETER(iserror);
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(len);
    for(int i=0; i<2; ++i) {
        hd = &((struct NaClHostDesc*)xchangedata)[i];
        lind_fd = ((int*)data)[i];
        NaClHostDescCtor(hd, lind_fd, NACL_ABI_O_RDWR);
        ((int*)data)[i] = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd)));
    }
    return retval;
}

struct poll_map
{
    int nacl_fd;
    int lind_fd;
};

int LindPollPreprocess(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void** xchangedata)
{
    int retval = 0;
    struct pollfd* pfds;
    struct pollfd* inpfds;
    struct poll_map* mapdata;
    int nfds;
    struct NaClDesc* ndp;
    UNREFERENCED_PARAMETER(inNum);
    nfds = (int)inArgs[0].ptr;
    if(nfds <= 0) {
        retval = -NACL_ABI_EINVAL;
        goto finish;
    }
    inpfds = (struct pollfd*)inArgs[2].ptr;
    if(NULL == inpfds) {
        retval = -NACL_ABI_EINVAL;
        goto finish;
    }
    *xchangedata = malloc(sizeof(int)+sizeof(struct poll_map)*nfds);
    if (NULL == *xchangedata) {
      retval = -NACL_ABI_ENOMEM;
      goto finish;
    }
    ((int*)(*xchangedata))[0] = nfds; //first sizeof(int) bytes contains # of fds
    mapdata = (struct poll_map*)&((int*)(*xchangedata))[1]; //map data begins after sizeof(int) bytes
    pfds = malloc(sizeof(pfds)*nfds);
    if (NULL == pfds) {
      retval = -NACL_ABI_ENOMEM;
      goto cleanup_xdata;
    }
    NaClFastMutexLock(&nap->desc_mu);
    for(int i=0; i<nfds; ++i) {
        pfds[i] = inpfds[i];
        ndp = NaClGetDescMu(nap, inpfds[i].fd);
        if(NULL == ndp || ndp->base.vtbl != (struct NaClRefCountVtbl const *)&kNaClDescIoDescVtbl) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup_pfds;
        }
        pfds[i].fd = ((struct NaClDescIoDesc*)ndp)->hd->d;
        mapdata[i].nacl_fd = inpfds[i].fd;
        mapdata[i].lind_fd = pfds[i].fd;
    }
    NaClFastMutexUnlock(&nap->desc_mu);
    inArgs[2].ptr = (uint64_t)(uintptr_t)pfds;
    goto finish;
cleanup_pfds:
    free(pfds);
cleanup_xdata:
    free(*xchangedata);
finish:
    return retval;
}

int LindPollPostprocess(struct NaClApp *nap, int iserror, int* code, char* data, int len, void* xchangedata)
{
    int retval = 0;
    struct poll_map* mapdata;
    int nfds;
    struct pollfd* pfds;
    UNREFERENCED_PARAMETER(nap);
    UNREFERENCED_PARAMETER(iserror);
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(len);
    nfds = ((int*)xchangedata)[0]; //first sizeof(int) bytes contains # of fds
    mapdata = (struct poll_map*)&((int*)xchangedata)[1]; //map data begins after sizeof(int) bytes
    pfds = (struct pollfd*)data;
    for(int i=0; i<nfds; ++i) {
        for(int i=0; i<nfds; ++i) {
            if(pfds[i].fd == mapdata[i].lind_fd) {
                pfds[i].fd = mapdata[i].nacl_fd;
            }
        }
    }
    return retval;
}

int LindPollCleanup(struct NaClApp *nap, uint32_t inNum, LindArg* inArgs, void* xchangedata)
{
    UNREFERENCED_PARAMETER(nap);
    UNREFERENCED_PARAMETER(inNum);
    NaClLog(3, "Entering LindSelectCleanup\n");
    free((void*)inArgs[2].ptr);
    free(xchangedata);
    NaClLog(3, "Exiting LindSelectCleanup\n");
    return 0;
}

StubType stubs[56]  =   {{NULL, NULL, NULL}, // 0
                         {NULL, NULL, NULL}, // 1 LIND_debug_noop
                         {NULL, NULL, NULL}, // 2 LIND_safe_fs_access
                         {NULL, NULL, NULL}, // 3 LIND_debug_trace
                         {NULL, NULL, NULL}, // 4 LIND_safe_fs_unlink
                         {NULL, NULL, NULL}, // 5 LIND_safe_fs_link
                         {NULL, NULL, NULL}, // 6 LIND_safe_fs_chdir
                         {NULL, NULL, NULL}, // 7 LIND_safe_fs_mkdir
                         {NULL, NULL, NULL}, // 8 LIND_safe_fs_rmdir
                         {NULL, NULL, NULL}, // 9 LIND_safe_fs_xstat
                         {NULL, NULL, NULL}, // 10 LIND_safe_fs_open
                         {NULL, NULL, NULL}, // 11
                         {NULL, NULL, NULL}, // 12
                         {NULL, NULL, NULL}, // 13
                         {NULL, NULL, NULL}, // 14
                         {NULL, NULL, NULL}, // 15
                         {NULL, NULL, NULL}, // 16
                         {NULL, NULL, NULL}, // 17
                         {NULL, NULL, NULL}, // 18
                         {LindCommonPreprocess, NULL, NULL}, // 19 LIND_safe_fs_fstatfs
                         {NULL, NULL, NULL}, // 20
                         {NULL, NULL, NULL}, // 21
                         {NULL, NULL, NULL}, // 22
                         {NULL, NULL, NULL}, // 23
                         {NULL, NULL, NULL}, // 24
                         {NULL, NULL, NULL}, // 25
                         {NULL, NULL, NULL}, // 26
                         {NULL, NULL, NULL}, // 27
                         {LindCommonPreprocess, NULL, NULL}, // 28 LIND_safe_fs_fcntl
                         {NULL, NULL, NULL}, // 29
                         {NULL, NULL, NULL}, // 30
                         {NULL, NULL, NULL}, // 31
                         {LindSocketPreprocess, LindSocketPostprocess, NULL}, // 32 LIND_safe_net_socket
                         {LindCommonPreprocess, NULL, NULL}, // 33 LIND_safe_net_bind
                         {LindCommonPreprocess, NULL, NULL}, // 34 LIND_safe_net_send
                         {NULL, NULL, NULL}, // 35 LIND_safe_net_sendto
                         {LindCommonPreprocess, NULL, NULL}, // 36 LIND_safe_net_recv
                         {LindCommonPreprocess, NULL, NULL}, // 37 LIND_safe_net_recvfrom
                         {LindCommonPreprocess, NULL, NULL}, // 38 LIND_safe_net_connect
                         {LindCommonPreprocess, NULL, NULL}, // 39 LIND_safe_net_listen
                         {LindAcceptPreprocess, LindAcceptPostprocess, NULL}, // 40 LIND_safe_net_accept
                         {NULL, NULL, NULL}, // 41
                         {NULL, NULL, NULL}, // 42
                         {LindCommonPreprocess, NULL, NULL}, // 43 LIND_safe_net_getsockopt
                         {LindCommonPreprocess, NULL, NULL}, // 44 LIND_safe_net_setsockopt
                         {LindCommonPreprocess, NULL, NULL}, // 45 LIND_safe_net_shutdown
                         {LindSelectPreprocess, LindSelectPostprocess, LindSelectCleanup}, // 46 LIND_safe_net_select
                         {NULL, NULL, NULL}, // 47
                         {LindPollPreprocess, LindPollPostprocess, LindPollCleanup}, // 48 LIND_safe_net_poll
                         {LindSocketPairPreprocess, LindSocketPairPostprocess, NULL}, // 49 LIND_safe_net_socketpair
                         {NULL, NULL, NULL}, // 50
                         {NULL, NULL, NULL}, // 51
                         {NULL, NULL, NULL}, // 52
                         {NULL, NULL, NULL}, // 53
                         {NULL, NULL, NULL}, // 54
                         {NULL, NULL, NULL},}; // 55

static int NaClCopyZStr(struct NaClApp *nap,
                        char           *dst_buffer,
                        size_t         dst_buffer_bytes,
                        uintptr_t      src_sys_addr) {
  NaClCopyTakeLock(nap);
  strncpy(dst_buffer, (char *) src_sys_addr, dst_buffer_bytes);
  NaClCopyDropLock(nap);

  /* POSIX strncpy pads with NUL characters */
  if (dst_buffer[dst_buffer_bytes - 1] != '\0') {
    dst_buffer[dst_buffer_bytes - 1] = '\0';
    return 0;
  }
  return 1;
}

int32_t NaClSysLindSyscall(struct NaClAppThread *natp,
                           uint32_t callNum,
                           uint32_t inNum,
                           void* inArgs,
                           uint32_t outNum,
                           void* outArgs)
{
    struct NaClApp *nap = natp->nap;
    int retval = -NACL_ABI_EINVAL;
    uintptr_t argSysAddr;
    char stringArg[NACL_CONFIG_PATH_MAX];
    LindArg inArgSys[MAX_INARGS];
    LindArg outArgSys[MAX_OUTARGS];
    PyObject* callArgs = NULL;
    PyObject* apiArg = NULL;
    PyObject* response = NULL;
    unsigned int i;
    int offset;
    int _code;
    int _isError;
    char* _data;
    int _len;
    void* xchangeData;

    NaClLog(3, "Entered NaClSysLindSyscall callNum=%8u inNum=%8u outNum=%8u\n", callNum, inNum, outNum);

    if(inNum>MAX_INARGS || outNum>MAX_OUTARGS) {
        NaClLog(LOG_ERROR, "NaClSysLindSyscall: Number of in/out arguments too large\n");
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if((inNum && !inArgs) || (outNum && !outArgs)) {
        NaClLog(LOG_ERROR, "NaClSysLindSyscall: in/out arguments are NULL\n");
        retval = -NACL_ABI_EFAULT;
        goto cleanup;
    }

    if(inNum && !NaClCopyInFromUser(nap, inArgSys, (uintptr_t)inArgs, sizeof(LindArg)*inNum)) {
        NaClLog(LOG_ERROR, "NaClSysLindSyscall: invalid input argument address\n");
        retval = -NACL_ABI_EFAULT;
        goto cleanup;
    }

    for(uint32_t i=0; i<inNum; ++i) {
        if(inArgSys[i].type != AT_INT) {
            if(inArgSys[i].ptr) {
                argSysAddr = NaClUserToSysAddrRange(nap, (uintptr_t)inArgSys[i].ptr, inArgSys[i].len);
                if(kNaClBadAddress == argSysAddr) {
                    NaClLog(LOG_ERROR, "NaClSysLindSyscall: invalid input data address\n");
                    retval = -NACL_ABI_EFAULT;
                    goto cleanup;
                }
                inArgSys[i].ptr = argSysAddr;
            } else if(inArgSys[i].type == AT_DATA || inArgSys[i].type == AT_STRING) {
                NaClLog(LOG_ERROR, "NaClSysLindSyscall: mandatory input is NULL\n");
                retval = -NACL_ABI_EFAULT;
                goto cleanup;
            }
        }
    }

    if(outNum && !NaClCopyInFromUser(nap, outArgSys, (uintptr_t)outArgs, sizeof(LindArg)*outNum)) {
        NaClLog(LOG_ERROR, "NaClSysLindSyscall: invalid output argument address\n");
        retval = -NACL_ABI_EFAULT;
        goto cleanup;
    }

    /*
    // For debugging
    for(int i=0; i<(int)inNum; ++i) {
        DumpArg(&inArgSys[i]);
    }

    for(int i=0; i<(int)outNum; ++i) {
        DumpArg(&outArgSys[i]);
    }*/

    if(stubs[callNum].pre) {
        retval = stubs[callNum].pre(nap, inNum, inArgSys, &xchangeData);
        if(retval) {
            goto cleanup;
        }
    }

    callArgs = PyList_New(0);
    apiArg = PyTuple_New(2);
    PyTuple_SetItem(apiArg, 0, PyInt_FromLong(callNum));
    PyTuple_SetItem(apiArg, 1, callArgs);

    for(i=0; i<inNum; ++i) {
        switch(inArgSys[i].type) {
        case AT_INT:
            NaClLog(3, "Int argument: %"NACL_PRId64", %"NACL_PRIu64"\n", *(int64_t*)&inArgSys[i].ptr, inArgSys[i].len);
            PyList_Append(callArgs, PyInt_FromLong(*(int64_t*)&inArgSys[i].ptr));
            break;
        case AT_STRING:
        case AT_STRING_OPTIONAL:
            if(inArgSys[i].ptr) {
                if (!NaClCopyZStr(nap, stringArg, sizeof(stringArg), (uintptr_t)inArgSys[i].ptr)) {
                    if (stringArg[0] == '\0') {
                        NaClLog(LOG_ERROR, "NaClSysLindSyscall: input string is empty\n");
                        retval = -NACL_ABI_EFAULT;
                    } else {
                        NaClLog(LOG_ERROR, "NaClSysLindSyscall: input string is too long (>%d)\n", NACL_CONFIG_PATH_MAX);
                        retval = -NACL_ABI_ENAMETOOLONG;
                    }
                    goto cleanup;
                }
                NaClLog(3, "String argument: %s\n", stringArg);
                PyList_Append(callArgs, PyString_FromString(stringArg));
            } else if(inArgSys[i].type == AT_STRING_OPTIONAL) {
                NaClLog(3, "Optional empty string argument\n");
                PyList_Append(callArgs, Py_None);
                Py_INCREF(Py_None);
            } else {
                NaClLog(LOG_ERROR, "NaClSysLindSyscall: input string is NULL\n");
                retval = -NACL_ABI_EFAULT;
                goto cleanup;
            }
            break;
        case AT_DATA:
        case AT_DATA_OPTIONAL:
            if(inArgSys[i].ptr) {
                NaClLog(3, "Data argument of length: %u\n", (unsigned int)inArgSys[i].len);
                NaClXMutexLock(&nap->mu);
                PyList_Append(callArgs, PyString_FromStringAndSize((char*)inArgSys[i].ptr, inArgSys[i].len));
                NaClXMutexUnlock(&nap->mu);
            } else if(inArgSys[i].type == AT_DATA_OPTIONAL) {
                NaClLog(3, "Optional empty data argument\n");
                PyList_Append(callArgs, Py_None);
                Py_INCREF(Py_None);
            } else {
                NaClLog(LOG_ERROR, "NaClSysLindSyscall: input data is NULL\n");
                retval = -NACL_ABI_EFAULT;
                goto cleanup;
            }
            break;
        default:
            NaClLog(LOG_ERROR, "NaClSysLindSyscall: invalid input data type\n");
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
    }

    response = CallPythonFunc(context, "LindSyscall", apiArg);
    GOTO_ERROR_IF_NULL(response);
    ParseResponse(response, &_isError, &_code, &_data, &_len);
    if(!_isError) {
        if(stubs[callNum].post) {
            stubs[callNum].post(nap, _isError, &_code, _data, _len, xchangeData);
        }
        if(outNum == 1) {
            assert(((unsigned int)_len)<=outArgSys[0].len);
            if(!NaClCopyOutToUser(nap, (uintptr_t)outArgSys[0].ptr, _data, _len)) {
                retval = -NACL_ABI_EFAULT;
                goto cleanup;
            }
        } else if (outNum > 1) {
            offset = 0;
            for(i=0; i<outNum; ++i) {
                NaClLog(3, "Out#%d, len=%"NACL_PRIu32", maxlen=%"NACL_PRIu64"\n",i, (unsigned int)(((int*)_data)[i]), outArgSys[i].len);
                assert(((unsigned int)(((int*)_data)[i]))<=outArgSys[i].len);
                if(!NaClCopyOutToUser(nap, (uintptr_t)outArgSys[i].ptr, _data+sizeof(int)*outNum+offset, ((int*)_data)[i])) {
                    retval = -NACL_ABI_EFAULT;
                    goto cleanup;
                }
                offset += ((int*)_data)[i];
            }
        }
    }
    if(stubs[callNum].clean) {
        stubs[callNum].clean(nap, inNum, inArgSys, xchangeData);
    }
    retval = _isError?-_code:_code;
    goto cleanup;
error:
    PyErr_Print();
    NaClLog(LOG_ERROR, "NaClSysLindSyscall: Python error\n");
cleanup:
    Py_XDECREF(apiArg);
    Py_XDECREF(response);
    return retval;
}
