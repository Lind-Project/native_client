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
#include "native_client/src/shared/platform/nacl_host_desc.h"

#include "native_client/src/include/nacl_assert.h"

#include "native_client/src/trusted/desc/nacl_desc_io.h"

#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/lind_syscalls.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/sel_mem.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_copy.h"
#include "native_client/src/trusted/service_runtime/include/bits/mman.h"
#include "native_client/src/trusted/service_runtime/include/sys/stat.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_common.h"

#if !defined(SIZE_T_MAX)
# define SIZE_T_MAX   (~(size_t) 0)
#endif

#define REPY_RELPATH "../repy/"

static const size_t kMaxUsableFileSize = (SIZE_T_MAX >> 1);

#define GOTO_ERROR_IF_NULL(x) if(!(x)) {goto error;}

PyObject* repylib = NULL;
PyObject* code = NULL;
PyObject* context = NULL;

static int initialized = 0;

typedef enum _LindArgType {AT_INT, AT_STRING, AT_STRING_OPTIONAL, AT_DATA, AT_DATA_OPTIONAL} LindArgType;

typedef struct _LindArg
{
    LindArgType type;
    uint64_t ptr;
    uint64_t len;
} LindArg;

PyObject* CallPythonFunc(PyObject* context, const char* func, PyObject* args)
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

PyObject* CallPythonFunc0(PyObject* context, const char* func)
{
    PyObject* func_obj = NULL;
    PyObject* args = NULL;
    PyObject* result = NULL;
    func_obj = PyDict_GetItemString(context, func);
    GOTO_ERROR_IF_NULL(func_obj);
    args = Py_BuildValue("()");
    GOTO_ERROR_IF_NULL(args);
    result = PyObject_CallObject(func_obj, args);
    GOTO_ERROR_IF_NULL(result);
    return result;
error:
    PyErr_Print();
    Py_XDECREF(func_obj);
    Py_XDECREF(args);
    return 0;
}

PyObject* CallPythonFunc1(PyObject* context, const char* func, PyObject* arg)
{
    PyObject* func_obj = NULL;
    PyObject* args = NULL;
    PyObject* result = NULL;
    func_obj = PyDict_GetItemString(context, func);
    GOTO_ERROR_IF_NULL(func_obj);
    args = Py_BuildValue("(O)", arg);
    GOTO_ERROR_IF_NULL(args);
    result = PyObject_CallObject(func_obj, args);
    GOTO_ERROR_IF_NULL(result);
    return result;
error:
    PyErr_Print();
    Py_XDECREF(func_obj);
    Py_XDECREF(args);
    return 0;
}

int LindPythonInit(void)
{
    PyObject* path = NULL;
    PyObject* repylib_name = NULL;
    PyObject* result = NULL;
    PyObject* repy_main_func = NULL;
    PyObject* repy_main_args = NULL;
    char* argv[] = {"dummy"};

    if(initialized++) {
        return 1;
    }
    Py_SetProgramName("dummy");
    Py_InitializeEx(0);
    PySys_SetArgvEx(1, argv, 0);

    path = PySys_GetObject("path");
    GOTO_ERROR_IF_NULL(path);
    PyList_Append(path, PyString_FromString(REPY_RELPATH));

    repylib_name = PyString_FromString("repylib");
    repylib = PyImport_Import(repylib_name);
    GOTO_ERROR_IF_NULL(repylib);
    repy_main_func = PyObject_GetAttrString(repylib, "repy_main");
    GOTO_ERROR_IF_NULL(repy_main_func);
    repy_main_args = Py_BuildValue("([sssss])", "lind", "--safebinary", REPY_RELPATH"restrictions.lind",
            REPY_RELPATH"lind_server.py", "./dummy.nexe");
    result = PyObject_CallObject(repy_main_func, repy_main_args);
    GOTO_ERROR_IF_NULL(result);
    PyArg_ParseTuple(result, "OO", &code, &context);
    GOTO_ERROR_IF_NULL(code && context);
    result = PyEval_EvalCode((PyCodeObject*)code, context, context);
    GOTO_ERROR_IF_NULL(result);
    return 1;
error:
    initialized = 0;
    PyErr_Print();
    return 0;
}

int LindPythonFinalize(void)
{
    int retval = 0;
    PyObject* repy_finalize_func = NULL;
    PyObject* repy_finalize_args = NULL;
    PyObject* result = NULL;
    if(!initialized) {
        return 0;
    }
    result = CallPythonFunc0(context, "finalize");
    GOTO_ERROR_IF_NULL(result);
    repy_finalize_func = PyObject_GetAttrString(repylib, "finalize");
    GOTO_ERROR_IF_NULL(repy_finalize_func);
    repy_finalize_args = Py_BuildValue("()");
    result = PyObject_CallObject(repy_finalize_func, repy_finalize_args);
    GOTO_ERROR_IF_NULL(result);
    Py_Finalize();
    initialized = 0;
    retval = 1;
    goto cleanup;
error:
    PyErr_Print();
cleanup:
    Py_XDECREF(repy_finalize_func);
    Py_XDECREF(result);
    Py_XDECREF(code);
    Py_XDECREF(context);
    Py_XDECREF(repylib);
    return retval;
}

int GetHostFdFromLindFd(int lindFd)
{
    int retval = -1;
    PyObject* pyLindFd = NULL;
    PyObject* pyHostFd = NULL;
    if(lindFd < 0) {
        goto cleanup;
    }
    pyLindFd = PyInt_FromLong(lindFd);
    pyHostFd = CallPythonFunc1(context, "GetHostFdFromLindFd", pyLindFd);
    GOTO_ERROR_IF_NULL(pyHostFd);
    if(!PyInt_CheckExact(pyHostFd)) {
        goto error;
    }
    retval = (int)PyInt_AsLong(pyHostFd);
    goto cleanup;
error:
    PyErr_Print();
cleanup:
    Py_XDECREF(pyLindFd);
    Py_XDECREF(pyHostFd);
    NaClLog(3, "host_fd:%d for lind_fd:%d\n", retval, lindFd);
    return retval;
}

int ParseResponse(PyObject* response, int* isError, int* code, char** dataOrMessage, int* len)
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
    retval = 1;
    goto cleanup;
error:
    NaClLog(LOG_ERROR, "ParseResponse Python error");
    PyErr_Print();
cleanup:
    Py_XDECREF(attrIsError);
    Py_XDECREF(attrCode);
    Py_XDECREF(attrDataOrMessage);
    return retval;
}

void DumpArg(const LindArg *arg)
{
    printf("%d:%lX:%lu\n", arg->type, arg->ptr, arg->len);
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

    callArgs = PyList_New(0);
    apiArg = PyTuple_New(2);
    PyTuple_SetItem(apiArg, 0, PyInt_FromLong(callNum));
    PyTuple_SetItem(apiArg, 1, callArgs);

    for(i=0; i<inNum; ++i) {
        switch(inArgSys[i].type) {
        case AT_INT:
            NaClLog(3, "Int argument: %ld, %lu\n", *(int64_t*)&inArgSys[i].ptr, inArgSys[i].len);
            PyList_Append(callArgs, PyInt_FromLong(*(int64_t*)&inArgSys[i].ptr));
            break;
        case AT_STRING:
        case AT_STRING_OPTIONAL:
            if(inArgSys[i].ptr) {
                if (!NaClCopyInFromUserZStr(nap, stringArg, sizeof(stringArg), (uintptr_t)inArgSys[i].ptr)) {
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
                argSysAddr = NaClUserToSysAddrRange(nap, (uintptr_t)inArgSys[i].ptr, inArgSys[i].len);
                if(argSysAddr == kNaClBadAddress) {
                    NaClLog(LOG_ERROR, "NaClSysLindSyscall: invalid input data address\n");
                    retval = -NACL_ABI_EFAULT;
                    goto cleanup;
                }
                NaClLog(3, "Data argument of length: %u\n", (unsigned int)inArgSys[i].len);
                NaClXMutexLock(&nap->mu);
                PyList_Append(callArgs, PyString_FromStringAndSize((char*)argSysAddr, inArgSys[i].len));
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
        if(outNum == 1) {
            assert(((unsigned int)_len)<=outArgSys[0].len);
            if(!NaClCopyOutToUser(nap, (uintptr_t)outArgSys[0].ptr, _data, _len)) {
                retval = -NACL_ABI_EFAULT;
                goto cleanup;
            }
        } else if (outNum > 1) {
            offset = 0;
            for(i=0; i<outNum; ++i) {
                assert(((unsigned int)(((int*)_data)[i]))<outArgSys[i].len);
                if(!NaClCopyOutToUser(nap, (uintptr_t)outArgSys[i].ptr, _data+sizeof(int)*outNum+offset, ((int*)_data)[i])) {
                    retval = -NACL_ABI_EFAULT;
                    goto cleanup;
                }
                offset += ((int*)_data)[i];
            }
        }
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

static INLINE int NaClMapFlagMap(int nacl_map_flags) {
  int host_os_flags;

  host_os_flags = 0;
#define M(H) do { \
    if (0 != (nacl_map_flags & NACL_ABI_ ## H)) { \
      host_os_flags |= H; \
    } \
  } while (0)
  M(MAP_SHARED);
  M(MAP_PRIVATE);
  M(MAP_FIXED);
  M(MAP_ANONYMOUS);
#undef M

  return host_os_flags;
}

/*
 * TODO(bsy): handle the !NACL_ABI_MAP_FIXED case.
 */
uintptr_t NaClHostDescMapLind(int hostFd,
                          struct NaClDescEffector *effp,
                          void                *start_addr,
                          size_t              len,
                          int                 prot,
                          int                 flags,
                          nacl_off64_t        offset) {
  int   desc;
  void  *map_addr;
  int   host_prot;
  int   host_flags;
  UNREFERENCED_PARAMETER(effp);

  NaClLog(4,
          ("NaClHostDescMap(0x%08"NACL_PRIxPTR", "
           "0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxS", "
           "0x%x, 0x%x, 0x%08"NACL_PRIx64")\n"),
          (uintptr_t) hostFd,
          (uintptr_t) start_addr,
          len,
          prot,
          flags,
          (int64_t) offset);
  if (-1 == hostFd && 0 == (flags & NACL_ABI_MAP_ANONYMOUS)) {
    NaClLog(LOG_FATAL, "NaClHostDescMap: 'this' is NULL and not anon map\n");
  }

  prot &= (NACL_ABI_PROT_READ | NACL_ABI_PROT_WRITE);
  /* may be PROT_NONE too, just not PROT_EXEC */


  if (flags & NACL_ABI_MAP_ANONYMOUS) {
    desc = -1;
  } else {
    desc = hostFd;
  }
  /*
   * Translate flags, prot to host_flags, host_prot.
   */
  host_flags = NaClMapFlagMap(flags);
  host_prot = NaClProtMap(prot);

  NaClLog(4, "NaClHostDescMap: host_flags 0x%x, host_prot 0x%x\n",
          host_flags, host_prot);

  map_addr = mmap(start_addr, len, host_prot, host_flags, desc, offset);

  if (MAP_FAILED == map_addr) {
    NaClLog(LOG_INFO,
            ("NaClHostDescMap: "
             "mmap(0x%08"NACL_PRIxPTR", 0x%"NACL_PRIxS", "
             "0x%x, 0x%x, 0x%d, 0x%"NACL_PRIx64")"
             " failed, errno %d.\n"),
            (uintptr_t) start_addr, len, host_prot, host_flags, desc,
            (int64_t) offset,
            errno);
    return -NaClXlateErrno(errno);
  }
  if (0 != (flags & NACL_ABI_MAP_FIXED) && map_addr != start_addr) {
    NaClLog(LOG_FATAL,
            ("NaClHostDescMap: mmap with MAP_FIXED not fixed:"
             " returned 0x%08"NACL_PRIxPTR" instead of 0x%08"NACL_PRIxPTR"\n"),
            (uintptr_t) map_addr,
            (uintptr_t) start_addr);
  }
  NaClLog(4, "NaClHostDescMap: returning 0x%08"NACL_PRIxPTR"\n",
          (uintptr_t) start_addr);

  return (uintptr_t) start_addr;
}

/*
 * Not quite a copy ctor.  Call it a translating ctor, since the
 * struct nacl_abi_stat POD object is constructed from the
 * nacl_host_stat_t POD object by element-wise copying.
 */
int32_t NaClAbiStatHostDescStatXlateCtorLind(struct nacl_abi_stat    *dst,
                                         nacl_host_stat_t const  *src) {
  nacl_abi_mode_t m;

  memset(dst, 0, sizeof *dst);

  dst->nacl_abi_st_dev = 0;
#if defined(NACL_MASK_INODES)
  dst->nacl_abi_st_ino = NACL_FAKE_INODE_NUM;
#else
  dst->nacl_abi_st_ino = src->st_ino;
#endif

  switch (src->st_mode & S_IFMT) {
    case S_IFREG:
      m = NACL_ABI_S_IFREG;
      break;
    case S_IFDIR:
      m = NACL_ABI_S_IFDIR;
      break;
#if defined(S_IFCHR)
    case S_IFCHR:
      /* stdin/out/err can be inherited, so this is okay */
      m = NACL_ABI_S_IFCHR;
      break;
#endif
    default:
      NaClLog(LOG_INFO,
              ("NaClAbiStatHostDescStatXlateCtor:"
               " Unusual NaCl descriptor type (not constructible)."
               " The NaCl app has a file with st_mode = 0%o."
               " (This is normal for std{in,out,err}, or other"
               " inherited/injected files.)\n"),
              src->st_mode);
      m = NACL_ABI_S_UNSUP;
  }
  if (0 != (src->st_mode & S_IRUSR)) {
      m |= NACL_ABI_S_IRUSR;
  }
  if (0 != (src->st_mode & S_IWUSR)) {
      m |= NACL_ABI_S_IWUSR;
  }
  if (0 != (src->st_mode & S_IXUSR)) {
      m |= NACL_ABI_S_IXUSR;
  }
  dst->nacl_abi_st_mode = m;
  dst->nacl_abi_st_nlink = src->st_nlink;
  dst->nacl_abi_st_uid = -1;  /* not root */
  dst->nacl_abi_st_gid = -1;  /* not wheel */
  dst->nacl_abi_st_rdev = 0;
  dst->nacl_abi_st_size = (nacl_abi_off_t) src->st_size;
  dst->nacl_abi_st_blksize = 0;
  dst->nacl_abi_st_blocks = 0;
  dst->nacl_abi_st_atime = src->st_atime;
  dst->nacl_abi_st_mtime = src->st_mtime;
  dst->nacl_abi_st_ctime = src->st_ctime;

  /*
   * For now, zero these fields.  We may want to expose the
   * corresponding values if the underlying host OS supports
   * nanosecond resolution timestamps later.
   */
  dst->nacl_abi_st_atimensec = 0;
  dst->nacl_abi_st_mtimensec = 0;
  dst->nacl_abi_st_ctimensec = 0;

  return 0;
}

/*
 * See NaClHostDescStat below.
 */
int NaClHostDescFstatLind(int hostFd,
                      nacl_host_stat_t     *nhsp) {
  if (fstat64(hostFd, nhsp) == -1) {
    return -errno;
  }
  return 0;
}

static int NaClDescIoDescFstatLind(int hostFd,
                               struct nacl_abi_stat    *statbuf) {
  int                   rv;
  nacl_host_stat_t      hstatbuf;

  rv = NaClHostDescFstatLind(hostFd, &hstatbuf);
  if (0 != rv) {
    return rv;
  }
  return NaClAbiStatHostDescStatXlateCtorLind(statbuf, &hstatbuf);
}

static INLINE size_t  size_min(size_t a, size_t b) {
  return (a < b) ? a : b;
}

static int32_t MunmapInternal(struct NaClApp *nap,
                              uintptr_t sysaddr, size_t length) {
  UNREFERENCED_PARAMETER(nap);
  /*
   * Overwrite current mapping with inaccessible, anonymous
   * zero-filled pages, which should be copy-on-write and thus
   * relatively cheap.  Do not open up an address space hole.
   */
  if (MAP_FAILED == mmap((void *) sysaddr,
                         length,
                         PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                         -1,
                         (off_t) 0)) {
    NaClLog(4, "mmap to put in anonymous memory failed, errno = %d\n", errno);
    return -NaClXlateErrno(errno);
  }
  NaClVmmapRemove(&nap->mem_map,
                  NaClSysToUser(nap, (uintptr_t) sysaddr) >> NACL_PAGESHIFT,
                  length >> NACL_PAGESHIFT,
                  NACL_VMMAP_ENTRY_ANONYMOUS);
  return 0;
}

/* Warning: sizeof(nacl_abi_off_t)!=sizeof(off_t) on OSX */
int32_t NaClCommonSysMmapInternLind(struct NaClApp        *nap,
                                void                  *start,
                                size_t                length,
                                int                   prot,
                                int                   flags,
                                int                   d,
                                nacl_abi_off_t        offset) {
  int                         allowed_flags;
  int                         hostDesc;
  uintptr_t                   usraddr;
  uintptr_t                   usrpage;
  uintptr_t                   sysaddr;
  uintptr_t                   endaddr;
  uintptr_t                   map_result;
  int                         holding_app_lock;
  struct nacl_abi_stat        stbuf;
  size_t                      alloc_rounded_length;
  nacl_off64_t                file_size;
  nacl_off64_t                file_bytes;
  nacl_off64_t                host_rounded_file_bytes;
  size_t                      alloc_rounded_file_bytes;

  holding_app_lock = 0;
  hostDesc = -1;

  allowed_flags = (NACL_ABI_MAP_FIXED | NACL_ABI_MAP_SHARED
                   | NACL_ABI_MAP_PRIVATE | NACL_ABI_MAP_ANONYMOUS);

  usraddr = (uintptr_t) start;

  if (0 != (flags & ~allowed_flags)) {
    NaClLog(2, "invalid mmap flags 0%o, ignoring extraneous bits\n", flags);
    flags &= allowed_flags;
  }

  if (0 != (flags & NACL_ABI_MAP_ANONYMOUS)) {
    /*
     * anonymous mmap, so backing store is just swap: no descriptor is
     * involved, and no memory object will be created to represent the
     * descriptor.
     */
    hostDesc = -1;
  } else {
    hostDesc = GetHostFdFromLindFd(d);
    if (-1 == hostDesc) {
      NaClLog(LOG_ERROR, "SysMmapInternLind: host fd not found");
      map_result = -NACL_ABI_EBADF;
      goto cleanup;
    }
  }

  /*
   * Starting address must be aligned to worst-case allocation
   * granularity.  (Windows.)
   */
  if (!NaClIsAllocPageMultiple(usraddr)) {
    NaClLog(2, "NaClSysMmap: address not allocation granularity aligned\n");
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  /*
   * Offset should be non-negative (nacl_abi_off_t is signed).  This
   * condition is caught when the file is stat'd and checked, and
   * offset is ignored for anonymous mappings.
   */
  if (offset < 0) {
    NaClLog(1,  /* application bug */
            "NaClSysMmap: negative file offset: %"NACL_PRIdNACL_OFF"\n",
            offset);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  /*
   * And offset must be a multiple of the allocation unit.
   */
  if (!NaClIsAllocPageMultiple((uintptr_t) offset)) {
    NaClLog(1,
            ("NaClSysMmap: file offset 0x%08"NACL_PRIxPTR" not multiple"
             " of allocation size\n"),
            (uintptr_t) offset);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  if (0 == length) {
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  alloc_rounded_length = NaClRoundAllocPage(length);
  if (alloc_rounded_length != length) {
    NaClLog(1,
            "mmap: rounded length to 0x%"NACL_PRIxS"\n",
            alloc_rounded_length);
  }

  if (-1 == hostDesc) {
    /*
     * Note: sentinel values are bigger than the NaCl module addr space.
     */
    file_size                = kMaxUsableFileSize;
    file_bytes               = kMaxUsableFileSize;
    host_rounded_file_bytes  = kMaxUsableFileSize;
    alloc_rounded_file_bytes = kMaxUsableFileSize;
  } else {
    /*
     * We stat the file to figure out its actual size.
     *
     * This is necessary because the POSIXy interface we provide
     * allows mapping beyond the extent of a file but Windows'
     * interface does not.  We simulate the POSIX behaviour on
     * Windows.
     */
    map_result = NaClDescIoDescFstatLind(hostDesc, &stbuf);
    if (0 != map_result) {
      goto cleanup;
    }
    /*
     * BUG(bsy): there's a race between this fstat and the actual mmap
     * below.  It's probably insoluble.  Even if we fstat again after
     * mmap and compared, the mmap could have "seen" the file with a
     * different size, after which the racing thread restored back to
     * the same value before the 2nd fstat takes place.
     */
    file_size = stbuf.nacl_abi_st_size;

    if (file_size < offset) {
      map_result = -NACL_ABI_EINVAL;
      goto cleanup;
    }

    file_bytes = file_size - offset;
    NaClLog(4,
            "NaClCommonSysMmapIntern: file_bytes 0x%016"NACL_PRIxNACL_OFF"\n",
            file_bytes);
    if ((nacl_off64_t) kMaxUsableFileSize < file_bytes) {
      host_rounded_file_bytes = kMaxUsableFileSize;
    } else {
      host_rounded_file_bytes = NaClRoundHostAllocPage((size_t) file_bytes);
    }

    ASSERT(host_rounded_file_bytes <= (nacl_off64_t) kMaxUsableFileSize);
    /*
     * We need to deal with NaClRoundHostAllocPage rounding up to zero
     * from ~0u - n, where n < 4096 or 65536 (== 1 alloc page).
     *
     * Luckily, file_bytes is at most kMaxUsableFileSize which is
     * smaller than SIZE_T_MAX, so it should never happen, but we
     * leave the explicit check below as defensive programming.
     */
    alloc_rounded_file_bytes =
      NaClRoundAllocPage((size_t) host_rounded_file_bytes);

    if (0 == alloc_rounded_file_bytes && 0 != host_rounded_file_bytes) {
      map_result = -NACL_ABI_ENOMEM;
      goto cleanup;
    }

    /*
     * NB: host_rounded_file_bytes and alloc_rounded_file_bytes can be
     * zero.  Such an mmap just makes memory (offset relative to
     * usraddr) in the range [0, alloc_rounded_length) inaccessible.
     */
  }

  /*
   * host_rounded_file_bytes is how many bytes we can map from the
   * file, given the user-supplied starting offset.  It is at least
   * one page.  If it came from a real file, it is a multiple of
   * host-OS allocation size.  it cannot be larger than
   * kMaxUsableFileSize.
   */
  length = size_min(alloc_rounded_length, (size_t) host_rounded_file_bytes);

  /*
   * Lock the addr space.
   */
  NaClXMutexLock(&nap->mu);

  NaClVmHoleOpeningMu(nap);

  holding_app_lock = 1;

  if (0 == (flags & NACL_ABI_MAP_FIXED)) {
    /*
     * The user wants us to pick an address range.
     */
    if (0 == usraddr) {
      /*
       * Pick a hole in addr space of appropriate size, anywhere.
       * We pick one that's best for the system.
       */
      usrpage = NaClVmmapFindMapSpace(&nap->mem_map,
                                      alloc_rounded_length >> NACL_PAGESHIFT);
      NaClLog(4, "NaClSysMmap: FindMapSpace: page 0x%05"NACL_PRIxPTR"\n",
              usrpage);
      if (0 == usrpage) {
        map_result = -NACL_ABI_ENOMEM;
        goto cleanup;
      }
      usraddr = usrpage << NACL_PAGESHIFT;
      NaClLog(4, "NaClSysMmap: new starting addr: 0x%08"NACL_PRIxPTR
              "\n", usraddr);
    } else {
      /*
       * user supplied an addr, but it's to be treated as a hint; we
       * find a hole of the right size in the app's address space,
       * according to the usual mmap semantics.
       */
      usrpage = NaClVmmapFindMapSpaceAboveHint(&nap->mem_map,
                                               usraddr,
                                               (alloc_rounded_length
                                                >> NACL_PAGESHIFT));
      NaClLog(4, "NaClSysMmap: FindSpaceAboveHint: page 0x%05"NACL_PRIxPTR"\n",
              usrpage);
      if (0 == usrpage) {
        NaClLog(4, "NaClSysMmap: hint failed, doing generic allocation\n");
        usrpage = NaClVmmapFindMapSpace(&nap->mem_map,
                                        alloc_rounded_length >> NACL_PAGESHIFT);
      }
      if (0 == usrpage) {
        map_result = -NACL_ABI_ENOMEM;
        goto cleanup;
      }
      usraddr = usrpage << NACL_PAGESHIFT;
      NaClLog(4, "NaClSysMmap: new starting addr: 0x%08"NACL_PRIxPTR"\n",
              usraddr);
    }
  }

  /*
   * Validate [usraddr, endaddr) is okay.
   */
  if (usraddr >= ((uintptr_t) 1 << nap->addr_bits)) {
    NaClLog(2,
            ("NaClSysMmap: start address (0x%08"NACL_PRIxPTR") outside address"
             " space\n"),
            usraddr);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  endaddr = usraddr + alloc_rounded_length;
  if (endaddr < usraddr) {
    NaClLog(0,
            ("NaClSysMmap: integer overflow -- "
             "NaClSysMmap(0x%08"NACL_PRIxPTR",0x%"NACL_PRIxS",0x%x,0x%x,%d,"
             "0x%08"NACL_PRIxPTR"\n"),
            usraddr, length, prot, flags, d, (uintptr_t) offset);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  /*
   * NB: we use > instead of >= here.
   *
   * endaddr is the address of the first byte beyond the target region
   * and it can equal the address space limit.  (of course, normally
   * the main thread's stack is there.)
   */
  if (endaddr > ((uintptr_t) 1 << nap->addr_bits)) {
    NaClLog(2,
            ("NaClSysMmap: end address (0x%08"NACL_PRIxPTR") is beyond"
             " the end of the address space\n"),
            endaddr);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  if (NaClSysCommonAddrRangeContainsExecutablePages_mu(nap,
                                                       usraddr,
                                                       length)) {
    NaClLog(2, "NaClSysMmap: region contains executable pages\n");
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  NaClVmIoPendingCheck_mu(nap,
                          (uint32_t) usraddr,
                          (uint32_t) (usraddr + length - 1));

  /*
   * Force NACL_ABI_MAP_FIXED, since we are specifying address in NaCl
   * app address space.
   */
  flags |= NACL_ABI_MAP_FIXED;

  /*
   * Never allow users to say that mmapped pages are executable.  This
   * is primarily for the service runtime's own bookkeeping -- prot is
   * used in NaClVmmapAddWithOverwrite -- since %cs restriction makes
   * page protection irrelevant, it doesn't matter that on many systems
   * (w/o NX) PROT_READ implies PROT_EXEC.
   */
  prot &= ~NACL_ABI_PROT_EXEC;

  /*
   * Exactly one of NACL_ABI_MAP_SHARED and NACL_ABI_MAP_PRIVATE is set.
   */
  if ((0 == (flags & NACL_ABI_MAP_SHARED))
      == (0 == (flags & NACL_ABI_MAP_PRIVATE))) {
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  sysaddr = NaClUserToSys(nap, usraddr);

  /* [0, length) */
  if (length > 0) {
    enum NaClVmmapEntryType vmmap_type;
    int max_prot;

    if (-1 == hostDesc) {
      NaClLog(4,
              ("NaClSysMmap: NaClDescIoDescMap(,,0x%08"NACL_PRIxPTR","
               "0x%08"NACL_PRIxS",0x%x,0x%x,0x%08"NACL_PRIxPTR")\n"),
              sysaddr, length, prot, flags, (uintptr_t) offset);
      map_result = NaClDescIoDescMapAnon(nap->effp,
                                         (void *) sysaddr,
                                         length,
                                         prot,
                                         flags,
                                         (off_t) offset);
    } else {
      /*
       * This is a fix for Windows, where we cannot pass a size that
       * goes beyond the non-page-rounded end of the file.
       */
      size_t length_to_map = size_min(length, (size_t) file_bytes);

      NaClLog(4,
              ("NaClSysMmap: (*ndp->Map)(,,0x%08"NACL_PRIxPTR","
               "0x%08"NACL_PRIxS",0x%x,0x%x,0x%08"NACL_PRIxPTR")\n"),
              sysaddr, length, prot, flags, (uintptr_t) offset);

      map_result = NaClHostDescMapLind(hostDesc,
                         nap->effp,
                         (void *) sysaddr,
                         length_to_map,
                         prot,
                         flags,
                         (off_t) offset);
    }
    /*
     * "Small" negative integers are errno values.  Larger ones are
     * virtual addresses.
     */
    if (NaClPtrIsNegErrno(&map_result)) {
      NaClLog(LOG_FATAL,
              ("NaClSysMmap: Map failed, but we"
               " cannot handle address space move, error %"NACL_PRIuS"\n"),
              (size_t) map_result);
    }
    if (map_result != sysaddr) {
      NaClLog(LOG_FATAL, "system mmap did not honor NACL_ABI_MAP_FIXED\n");
    }
    /*
     * windows nacl_host_desc implementation requires that PROT_NONE
     * memory be freed using VirtualFree rather than
     * UnmapViewOfFile.  TODO(bsy): remove this ugliness.
     */
    vmmap_type = (-1 == hostDesc || NACL_ABI_PROT_NONE == prot) ?
                 NACL_VMMAP_ENTRY_ANONYMOUS :
                 NACL_VMMAP_ENTRY_MAPPED;
    /*
     * TODO(phosek): we're recording potentially wrong info here, we shall add
     * attribute bits to NaClDesc about open flags and use that info instead.
     */
    max_prot = (-1 != hostDesc && (flags & NACL_ABI_MAP_SHARED)) ?
               prot : NACL_ABI_PROT_READ | NACL_ABI_PROT_WRITE;
    NaClVmmapAddWithOverwrite(&nap->mem_map,
                              NaClSysToUser(nap, sysaddr) >> NACL_PAGESHIFT,
                              length >> NACL_PAGESHIFT,
                              NaClProtMap(prot),
                              NaClProtMap(max_prot),
                              vmmap_type);
  } else {
    map_result = sysaddr;
  }
  /*
   * If we are mapping beyond the end of the file, we fill this space
   * with PROT_NONE pages.
   *
   * Windows forces us to expose a mixture of 64k and 4k pages, and we
   * expose the same mappings on other platforms.  For example,
   * suppose untrusted code requests to map 0x40000 bytes from a file
   * of extent 0x100.  We will create the following regions:
   *
   *       0-  0x100  A: Bytes from the file
   *   0x100- 0x1000  B: The rest of the 4k page is accessible but undefined
   *  0x1000-0x10000  C: The rest of the 64k page is inaccessible (PROT_NONE)
   * 0x10000-0x40000  D: Further 64k pages are also inaccessible (PROT_NONE)
   *
   * On Windows, a single MapViewOfFileEx() call creates A, B and C.
   * This call will not accept a size greater than 0x100, so we have
   * to create D separately.  The hardware requires B to be accessible
   * (whenever A is accessible), but Windows does not allow C to be
   * mapped as accessible.  This is unfortunate because it interferes
   * with how ELF dynamic linkers usually like to set up an ELF
   * object's BSS.
   */
  /* inaccessible: [length, alloc_rounded_length) */
  if (length < alloc_rounded_length) {
    /*
     * On Unix, this maps regions C and D as inaccessible.  On
     * Windows, it just maps region D; region C has already been made
     * inaccessible.
     */
    size_t map_len = alloc_rounded_length - length;
    map_result = MunmapInternal(nap, sysaddr + length, map_len);
    if (map_result != 0) {
      goto cleanup;
    }
  }
  NaClLog(3, "NaClSysMmap: got address 0x%08"NACL_PRIxPTR"\n",
          (uintptr_t) map_result);

  map_result = usraddr;

cleanup:
  if (holding_app_lock) {
    NaClVmHoleClosingMu(nap);
    NaClXMutexUnlock(&nap->mu);
  }

  /*
   * Check to ensure that map_result will fit into a 32-bit value. This is
   * a bit tricky because there are two valid ranges: one is the range from
   * 0 to (almost) 2^32, the other is from -1 to -4096 (our error range).
   * For a 32-bit value these ranges would overlap, but if the value is 64-bit
   * they will be disjoint.
   */
  if (map_result > UINT32_MAX
      && !NaClPtrIsNegErrno(&map_result)) {
    NaClLog(LOG_FATAL, "Overflow in NaClSysMmap: return address is "
                       "0x%"NACL_PRIxPTR"\n", map_result);
  }
  NaClLog(3, "NaClSysMmap: returning 0x%08"NACL_PRIxPTR"\n", map_result);

  return (int32_t) map_result;
}

int32_t NaClCommonSysMmapLind(struct NaClAppThread  *natp,
                              void                  *start,
                              size_t                length,
                              int                   prot,
                              int                   flags,
                              int                   d,
                              nacl_abi_off_t        *offp)
{
    struct NaClApp  *nap = natp->nap;
    int32_t         retval;
    uintptr_t       sysaddr;
    nacl_abi_off_t  offset;

    NaClLog(3,
          "Entered NaClSysMmapLind(0x%08"NACL_PRIxPTR",0x%"NACL_PRIxS","
          "0x%x,0x%x,%d,0x%08"NACL_PRIxPTR")\n",
          (uintptr_t) start, length, prot, flags, d, (uintptr_t) offp);

    if ((nacl_abi_off_t *) 0 == offp) {
    /*
     * This warning is really targetted towards trusted code,
     * especially tests that didn't notice the argument type change.
     * Unfortunatey, zero is a common and legitimate offset value, and
     * the compiler will not complain since an automatic type
     * conversion works.
     */
        NaClLog(LOG_WARNING,
            "NaClCommonSysMmapLind: NULL pointer used"
            " for offset in/out argument\n");
        return -NACL_ABI_EINVAL;
    }

    sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) offp, sizeof offset);
    if (kNaClBadAddress == sysaddr) {
        NaClLog(3,
            "NaClCommonSysMmapLind: offset in a bad untrusted memory location\n");
        retval = -NACL_ABI_EFAULT;
        goto cleanup;
    }
    offset = *(nacl_abi_off_t volatile *) sysaddr;

    NaClLog(4, " offset = 0x%08"NACL_PRIxNACL_OFF"\n", offset);

    retval = NaClCommonSysMmapInternLind(nap,
                                         start,
                                         length,
                                         prot,
                                         flags,
                                         d,
                                         offset);
cleanup:
      return retval;
}


#define CHECK_NOT_NULL(x) \
        if(!(x)) { return -EINVAL; }

#define LIND_API_PART1 \
        int retval = 0; \
        int _code = 0; \
        int _isError = 0; \
        char* _data = NULL; \
        int _len = 0; \
        int _offset = 0; \
        PyObject* callArgs = NULL; \
        PyObject* response = NULL;

#define LIND_API_PART2 \
        GOTO_ERROR_IF_NULL(callArgs); \
        response = CallPythonFunc(context, "LindSyscall", callArgs); \
        ParseResponse(response, &_isError, &_code, &_data, &_len); \
        retval = _isError?-_code:_code; \
        UNREFERENCED_PARAMETER(_offset);

#define LIND_API_PART3 \
        goto cleanup; \
        error: \
            PyErr_Print(); \
        cleanup: \
            Py_XDECREF(callArgs); \
            Py_XDECREF(response); \
            return retval;

#define COPY_DATA(var, maxlen) \
        if(!_isError) { \
            assert(_len<=(int)(maxlen));\
            if(var) { \
                assert(_data!=NULL); \
                memcpy((var), _data, _len); \
            } \
        }

#define COPY_DATA_OFFSET(var, maxlen, total, current) \
        if(!_isError) { \
            assert(((int*)_data)[(current)]<=(int)(maxlen));\
            if(var) { \
                assert(_data!=NULL); \
                memcpy((var), _data+sizeof(int)*(total)+_offset, ((int*)_data)[(current)]); \
            } \
        } \
        _offset += ((int*)_data)[(current)];

int lind_access (int version, const char *file)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[is])", LIND_safe_fs_access, version, file);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_unlink (const char *name)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[s])", LIND_safe_fs_unlink, name);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_link (const char *from, const char *to)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ss])", LIND_safe_fs_link, from, to);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_chdir (const char *name)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[s])", LIND_safe_fs_chdir, name);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_mkdir (int mode, const char *path)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[is])", LIND_safe_fs_mkdir, mode, path);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_rmdir (const char *path)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[is])", LIND_safe_fs_rmdir, path);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_xstat (int version, const char *path, struct stat *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[is])", LIND_safe_fs_xstat, version, path);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_open (int flags, int mode, const char *path)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iis])", LIND_safe_fs_open, flags, mode, path);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_close (int fd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[i])", LIND_safe_fs_close, fd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_read (int fd, int size, void *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_read, fd, size);
    LIND_API_PART2
    COPY_DATA(buf, size)
    LIND_API_PART3
}

int lind_write (int fd, size_t count, const void *buf)
{
    LIND_API_PART1
    CHECK_NOT_NULL(buf)
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_fs_write, fd, count, buf, count);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_lseek (off_t offset, int fd, int whence, off_t * ret)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_fs_lseek, offset, fd, whence);
    LIND_API_PART2
    COPY_DATA(ret, sizeof(*ret))
    LIND_API_PART3
}

int lind_fxstat (int fd, int version, struct stat *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_fxstat, fd, version);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_fstatfs (int fd, struct statfs *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[i])", LIND_safe_fs_fstatfs, fd);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_statfs (const char *path, struct statfs *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[s])", LIND_safe_fs_statfs, path);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_noop (void)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_debug_noop);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getpid (pid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_sys_getpid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_dup (int oldfd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[i])", LIND_safe_fs_dup, oldfd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_dup2 (int oldfd, int newfd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_dup, oldfd, newfd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getdents (int fd, size_t nbytes, char *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_getdents, fd, nbytes);
    LIND_API_PART2
    COPY_DATA(buf, nbytes)
    LIND_API_PART3
}

int lind_fcntl_get (int fd, int cmd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_fcntl, fd, cmd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_fcntl_set (int fd, int cmd, long set_op)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iil])", LIND_safe_fs_fcntl, fd, cmd, set_op);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_socket (int domain, int type, int protocol)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_net_socket, domain, type, protocol);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_bind (int sockfd, socklen_t addrlen, const struct sockaddr *addr)
{
    LIND_API_PART1
    CHECK_NOT_NULL(addr)
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_net_bind, sockfd, addrlen, addr, addrlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_send (int sockfd, size_t len, int flags, const void *buf)
{
    LIND_API_PART1
    CHECK_NOT_NULL(buf)
    callArgs = Py_BuildValue("(i[iiis#])", LIND_safe_net_send, sockfd, len, flags, buf, len);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_recv (int sockfd, size_t len, int flags, void *buf)
{
    LIND_API_PART1
    CHECK_NOT_NULL(buf)
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_net_recv, sockfd, len, flags);
    LIND_API_PART2
    COPY_DATA(buf, len)
    LIND_API_PART3
}

int lind_connect (int sockfd, socklen_t addrlen, const struct sockaddr *src_addr)
{
    LIND_API_PART1
    CHECK_NOT_NULL(src_addr)
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_net_connect, sockfd, addrlen, src_addr, addrlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_listen (int sockfd, int backlog)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_listen, sockfd, backlog);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_sendto (int sockfd, size_t len, int flags, socklen_t addrlen, const struct sockaddr_in *dest_addr, const void *buf)
{
    UNREFERENCED_PARAMETER(sockfd);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(addrlen);
    UNREFERENCED_PARAMETER(dest_addr);
    UNREFERENCED_PARAMETER(buf);
    /*CHECK_NOT_NULL(dest_addr);
    CHECK_NOT_NULL(buf);
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iiiis#s#])", LIND_safe_net_sendto, sockfd, len, addrlen, dest_addr, addrlen, buf, len);
    LIND_API_PART2
    LIND_API_PART3*/

    // unimplemented
    return 0;
}

int lind_accept (int sockfd, socklen_t addrlen)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_accept, sockfd, addrlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getpeername (int sockfd, socklen_t addrlen_in, __SOCKADDR_ARG addr, socklen_t * addrlen_out)
{
    UNREFERENCED_PARAMETER(sockfd);
    UNREFERENCED_PARAMETER(addrlen_in);
    UNREFERENCED_PARAMETER(addr);
    UNREFERENCED_PARAMETER(addrlen_out);
    /*LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_getpeername, sockfd, addrlen);
    LIND_API_PART2
    LIND_API_PART3*/

    // unimplemented
    return 0;
}

int lind_setsockopt (int sockfd, int level, int optname, socklen_t optlen, const void *optval)
{
    LIND_API_PART1
    CHECK_NOT_NULL(optval)
    callArgs = Py_BuildValue("(i[iiiis#])", LIND_safe_net_setsockopt, sockfd, level, optname, optlen, optval, optlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getsockopt (int sockfd, int level, int optname, socklen_t optlen, void *optval)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iiii])", LIND_safe_net_getsockopt, sockfd, level, optname, optlen);
    LIND_API_PART2
    COPY_DATA(optval, optlen)
    LIND_API_PART3
}

int lind_shutdown (int sockfd, int how)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_shutdown, sockfd, how);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_select (int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds,
        struct timeval *timeout, struct select_results *result)
{
    LIND_API_PART1
    PyObject* readFdObj = NULL;
    PyObject* writeFdObj = NULL;
    PyObject* exceptFdObj = NULL;
    PyObject* timeValObj = NULL;
    if(readfds) {
        readFdObj = PyString_FromStringAndSize((char*)readfds, sizeof(fd_set));
    } else {
        readFdObj = Py_None;
        Py_INCREF(readFdObj);
    }
    if(writefds) {
        writeFdObj = PyString_FromStringAndSize((char*)writefds, sizeof(fd_set));
    } else {
        writeFdObj = Py_None;
        Py_INCREF(writeFdObj);
    }
    if(exceptfds) {
        exceptFdObj = PyString_FromStringAndSize((char*)exceptfds, sizeof(fd_set));
    } else {
        exceptFdObj = Py_None;
        Py_INCREF(exceptFdObj);
    }
    if(timeout) {
        timeValObj = PyString_FromStringAndSize((char*)timeout, sizeof(struct timeval));
    } else {
        timeValObj = Py_None;
        Py_INCREF(timeValObj);
    }
    callArgs = Py_BuildValue("(i[iOOOO])", LIND_safe_net_select, nfds, readFdObj,
            writeFdObj, exceptFdObj, timeValObj);
    Py_XDECREF(readFdObj);
    Py_XDECREF(writeFdObj);
    Py_XDECREF(exceptFdObj);
    Py_XDECREF(timeValObj);
    LIND_API_PART2
    COPY_DATA(result, sizeof(*result))
    LIND_API_PART3
}

int lind_getifaddrs (int ifaddrs_buf_siz, void *ifaddrs)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[i])", LIND_safe_net_getifaddrs, ifaddrs_buf_siz);
    LIND_API_PART2
    COPY_DATA(ifaddrs, ifaddrs_buf_siz)
    LIND_API_PART3
}

int lind_recvfrom (int sockfd, size_t len, int flags, socklen_t addrlen, socklen_t * addrlen_out, void *buf, struct sockaddr *src_addr)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iiii])", LIND_safe_net_recvfrom, sockfd, len, flags, addrlen);
    LIND_API_PART2
    COPY_DATA_OFFSET(addrlen_out, sizeof(*addrlen_out), 3, 0)
    COPY_DATA_OFFSET(buf, len, 3, 1)
    COPY_DATA_OFFSET(src_addr, sizeof(*src_addr), 3, 2)
    LIND_API_PART3
}

int lind_poll (int nfds, int timeout, struct pollfd *fds_in, struct pollfd *fds_out)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_net_poll, nfds, timeout, fds_in, sizeof(struct pollfd)*nfds);
    LIND_API_PART2
    COPY_DATA(fds_out, sizeof(struct pollfd)*nfds)
    LIND_API_PART3
}

int lind_socketpair (int domain, int type, int protocol, int *fds)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_net_socketpair, domain, type, protocol);
    LIND_API_PART2
    COPY_DATA(fds, sizeof(int)*2)
    LIND_API_PART3
}

int lind_getuid (uid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_getuid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_geteuid (uid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_geteuid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_getgid (gid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_getgid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_getegid (gid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_getegid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_flock (int fd, int operation)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_flock, fd, operation);
    LIND_API_PART2
    LIND_API_PART3
}

