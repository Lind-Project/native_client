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

#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_copy.h"


#define GOTO_ERROR_IF_NULL(x) if(!(x)) {goto error;}

extern PyObject* context;

#define MAX_INARGS 16
#define MAX_OUTARGS 16

typedef enum _LindArgType {AT_INT, AT_STRING, AT_STRING_OPTIONAL, AT_DATA, AT_DATA_OPTIONAL} LindArgType;

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
