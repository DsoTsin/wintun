#ifdef WITH_PYTHON

#    ifdef MONOLITHIC_BUILD
#        define WIN32_LEAN_AND_MEAN 1
#        define MAYBE_WOW64
#        define _UNICODE
//"_USRDLL"
#        define WINTUN_VERSION_MAJ 0
#        define WINTUN_VERSION_MIN 14
#        define WINTUN_VERSION_REL 1
#        define WINTUN_VERSION "0.14.1"

#        define _WIN32_WINNT 0x0601
#        define WINVER 0x0601
#        define WINNT 1
#        define NTDDI_VERSION 0x06010000
#        define PY_SSIZE_T_CLEAN
#        include "driver.c"
#        include "logger.c"
#        include "main.c"
#        include "registry.c"
#        include "session.c"
#        include "adapter.c"
#        include "namespace.c"
#        include "rundll32.c"
#    else
#        include "wintun.h"
#    endif

#    include <Python.h>
#include <Windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#define _WINDNS_INCLUDED_
#include <iphlpapi.h>
#include <mstcpip.h>
#include <ip2string.h>

#    pragma comment(lib, "setupapi.lib")
// @see also https://github.com/doronz88/pytun-pmd3

PyDoc_STRVAR(wintun_error_doc, "This exception is raised when an error occurs. The accompanying value is\n\
either a string telling what went wrong or a pair (errno, string)\n\
representing an error returned by a system call, similar to the value\n\
accompanying os.error. See the module errno, which contains names for the\n\
error codes defined by the underlying operating system.");

static PyObject* py_wintun_error = NULL;

#define DEFAULT_RING_CAPCITY 0x400000

static void raise_error_from_errno(void) {
    PyErr_SetFromErrno(py_wintun_error);
}

static void raise_error(const char* errmsg) {
    PyErr_SetString(py_wintun_error, errmsg);
}

// netsh interface ipv6 set subinterface %1% mtu=%2%
typedef struct wintun_t {
    PyObject_HEAD WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    int capacity;
    char name[MAX_PATH];
    wchar_t addr4[32];
    wchar_t addr6[MAX_PATH];
    int mtu4;
    int mtu6;
    int proto_aware;
    int proto_bits;
} wintun_t;

LONG admin_err_cnt = 0;

BOOL IsRunAsAdmin() {
    BOOL isMember;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup))
    {
        isMember = FALSE;
        goto end;
    }
    if (!CheckTokenMembership(NULL, administratorsGroup, &isMember))
    {
        isMember = FALSE;
    }
    FreeSid(administratorsGroup);
end:
    return isMember;
}

static PyObject *
wintun_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    if (admin_err_cnt = 0) 
    {
        if (!IsRunAsAdmin())
        {
            InterlockedIncrement(&admin_err_cnt);
            raise_error("Unable to create TunTapDevice, you need to run as Administrator!!");
            Py_RETURN_NONE;
        }
    }
    wintun_t *tuntap = NULL;
    const char *name = NULL;
    const char* tun_type = "";
    const char *guid = "";
    int proto_aware = 1;
    char *kwlist[] = { "name", "type", "guid", "proto_aware", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sssp", kwlist, &name, &tun_type, &guid, &proto_aware))
    {
        return NULL;
    }
    tuntap = (wintun_t *)type->tp_alloc(type, 0);
    if (tuntap == NULL)
    {
        goto error;
    }
    wchar_t name1[MAX_PATH];
    wchar_t type1[MAX_PATH];
    wchar_t* stype = L"pytun-pmd3";
    size_t conv = 0;
    if (strlen(tun_type) > 0)
    {
        mbstowcs_s(&conv, type1, MAX_PATH, tun_type, -1);
        stype = type1;
    }
    if (!name)
    {
        name = "wintun";
    }
    mbstowcs_s(&conv, name1, MAX_PATH, name, -1);
    strcpy(tuntap->name, name);
    tuntap->capacity = DEFAULT_RING_CAPCITY;
    tuntap->proto_aware = proto_aware;
    tuntap->adapter = WintunOpenAdapter(name1);
    if (!tuntap->adapter)
    {
        tuntap->adapter = WintunCreateAdapter(name1, stype, NULL);
    }
    if (tuntap->adapter == 0) {
        goto error;
    }
    
    MIB_IF_ROW2 ifRow = {0};
    WintunGetAdapterLUID(tuntap->adapter, &ifRow.InterfaceLuid);
    GetIfEntry2(&ifRow);
    tuntap->mtu6 = ifRow.Mtu; 
    tuntap->mtu4 = ifRow.Mtu;

    return (PyObject *)tuntap;
error:
    if (tuntap != NULL) {
        if (tuntap->adapter) {
            WintunCloseAdapter(tuntap->adapter);
            tuntap->adapter = NULL;
        }
        type->tp_free(tuntap);
    }
    Py_RETURN_NONE;
}

static void
wintun_dealloc(PyObject *self)
{
    wintun_t *tuntap = (wintun_t *)self;
    if (tuntap->session != NULL)
    {
        WintunEndSession(tuntap->session);
        tuntap->session = NULL;
    }
    if (tuntap->adapter)
    {
        WintunCloseAdapter(tuntap->adapter);
        tuntap->adapter = NULL;
    }
    self->ob_type->tp_free(self);
}

static PyObject *
wintun_close(PyObject *self)
{
    wintun_t *tuntap = (wintun_t *)self;
    if (tuntap->session != NULL)
    {
        WintunEndSession(tuntap->session);
        tuntap->session = NULL;
    }
    if (tuntap->adapter)
    {
        WintunCloseAdapter(tuntap->adapter);
        tuntap->adapter = NULL;
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(wintun_close_doc, "close() -> None.\n\
Close the device.");

inline PyObject* new_buffer(unsigned int len) {
#if PY_MAJOR_VERSION >= 3
    return PyBytes_FromStringAndSize(NULL, len);
#else
    return PyString_FromStringAndSize(NULL, len);
#endif
}

static PyObject *
wintun_read(PyObject *self, PyObject *args, PyObject* kwds)
{
    wintun_t *tuntap = (wintun_t *)self;
    unsigned int rdlen;
    PyObject *buf = NULL;

    BYTE* packet = WintunReceivePacket(tuntap->session, &rdlen);
    if (packet)
    {
        if (tuntap->proto_aware == 0)
        {
            goto ready;
        }
        else // Aware
        {
            // v6 or v4
            if (((packet[0] >> 4) == 6 && (tuntap->proto_bits & 2) != 0)
                || (tuntap->proto_bits & 1) != 0)
            {
                goto ready;
            }
            else 
            {
                goto cleanup;
            }
        }
ready:
        buf = new_buffer(rdlen);
        memcpy(PyBytes_AS_STRING(buf), packet, rdlen);
        WintunReleaseReceivePacket(tuntap->session, packet);
        goto ret;
cleanup:
        WintunReleaseReceivePacket(tuntap->session, packet);
    }

ret:
    if (buf)
    {
        return buf;
    }
    else
    {
        DWORD LastError = GetLastError();
        if (LastError != ERROR_NO_MORE_ITEMS && LastError != ERROR_SUCCESS)
        {
            // ERROR_HANDLE_EOF ERROR_INVALID_DATA
            raise_error_from_errno();
        }
        Py_RETURN_NONE;
    }
}

PyDoc_STRVAR(wintun_read_doc, "read() -> non-blocking read a whole packet buffer, returned as a string.");

static PyObject* wintun_write(PyObject *self, PyObject *args) {
    wintun_t *tuntap = (wintun_t *)self;
    char *buf = NULL;
    Py_ssize_t len = 0;
    if (!PyArg_ParseTuple(args, "s#:write", &buf, &len))
    {
        return NULL;
    }
    size_t written = 0;
    // For pymobiledevice3
    static const char* LOOPBACK_HEADER = "\x00\x00\x86\xdd";
    if (len > 4 && memcmp(LOOPBACK_HEADER, buf, 4) == 0)
    {
        len -= 4;
        buf += 4;
    }
    BYTE *packet = WintunAllocateSendPacket(tuntap->session, len);
    if (packet)
    {
        memcpy(packet, buf, len);
        WintunSendPacket(tuntap->session, packet);
        written = len;
    }
    else
    {
        written = -1;
    }
    if (written < 0)
    {
        // ERROR_HANDLE_EOF ERROR_BUFFER_OVERFLOW
        raise_error_from_errno();
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyLong_FromSsize_t(written);
#else
    return PyInt_FromSsize_t(written);
#endif
}

PyDoc_STRVAR(wintun_write_doc, "write(str) -> number of bytes written.\n\
Write str to device.");

static PyObject* wintun_wait_read_event(PyObject* self, PyObject* args) {
    wintun_t* tuntap = (wintun_t*)self;
    HANDLE ev = WintunGetReadWaitEvent(tuntap->session);
    return PyLong_FromUnsignedLong( WaitForSingleObject(ev, INFINITE) );
}

PyDoc_STRVAR(wintun_wait_read_event_doc, "wait_read_event() .\n\
Wait read event signaled.");

static PyObject* wintun_up(PyObject* self) {
    wintun_t* tuntap = (wintun_t*)self;
    if (tuntap->session) {
        WintunEndSession(tuntap->session);
    }
    tuntap->session = WintunStartSession(tuntap->adapter, tuntap->capacity);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(wintun_up_doc, "up() .\n\
Start tunnel session.");

static PyObject* wintun_down(PyObject* self) {
    wintun_t* tuntap = (wintun_t*)self;
    if (tuntap->session) {
        WintunEndSession(tuntap->session);
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(wintun_down_doc, "down() .\n\
End tunnel session.");

static PyMethodDef wintun_meth[] = { { "close", (PyCFunction)wintun_close, METH_NOARGS, wintun_close_doc },
                                     { "read", (PyCFunction)wintun_read, METH_VARARGS, wintun_read_doc },
                                     { "write", (PyCFunction)wintun_write, METH_VARARGS, wintun_write_doc },
                                     { "up", (PyCFunction)wintun_up, METH_VARARGS, wintun_up_doc },
                                     { "down", (PyCFunction)wintun_down, METH_VARARGS, wintun_down_doc },
                                     { "wait_read_event", (PyCFunction)wintun_wait_read_event, METH_VARARGS, wintun_wait_read_event_doc },
                                     { NULL, NULL, 0, NULL } };

static PyObject *
wintun_readwait_event(PyObject *self, PyObject *args)
{
    wintun_t *tuntap = (wintun_t *)self;
    HANDLE ev = NULL;
    ev = WintunGetReadWaitEvent(tuntap->session);
#if PY_MAJOR_VERSION >= 3
        return PyLong_FromSsize_t((Py_ssize_t)ev);
#else
        return PyInt_FromSsize_t((Py_ssize_t)ev);
#endif
}

static PyObject*
wintun_get_name(PyObject* self, PyObject* args)
{
    wintun_t* tuntap = (wintun_t*)self;
#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(tuntap->name);
#else
    return PyString_FromString(tuntap->name);
#endif
}

static int
wintun_set_capacity(PyObject* self, PyObject* value, void* d)
{
    wintun_t* tuntap = (wintun_t*)self;
    tuntap->capacity = PyLong_AsLong(value);
    return 0;
}

static PyObject*
wintun_get_capacity(PyObject* self, void* d)
{
    wintun_t* tuntap = (wintun_t*)self;
    return PyLong_FromLong(tuntap->capacity);
}

#define MTU_INIT                    \
    int mtu = PyLong_AsLong(value); \
    if (mtu <= 0)                   \
    {                               \
        if (!PyErr_Occurred())      \
        {                           \
            raise_error("Bad MTU, should be > 0");\
        }                           \
        return -1;                  \
    }                               \
    if (mtu > 0xFFFF)               \
    {                               \
        if (!PyErr_Occurred())      \
        {                           \
            raise_error("Bad MTU, should be <= 0xFFFF");\
        }                           \
        return -1;                  \
    }

#if 0
// netsh interface ipv6 set subinterface %1% mtu=%2%
char buffer[MAX_PATH] = { 0 };
snprintf(buffer, MAX_PATH, "netsh interface ipv6 set subinterface %s mtu=%d", tuntap->name, mtu);
system(buffer);
#endif

static PyObject* wintun_get_mtu4(PyObject* self, void* d) {
    wintun_t* tuntap = (wintun_t*)self;
    return PyLong_FromLong(tuntap->mtu4);
}

static int wintun_set_mtu4(PyObject* self, PyObject* value, void* d) {
    wintun_t* tuntap = (wintun_t*)self;
    MTU_INIT
    if (mtu != tuntap->mtu4) {
        MIB_IPINTERFACE_ROW ipRow;
        InitializeIpInterfaceEntry(&ipRow);
        WintunGetAdapterLUID(tuntap->adapter, &ipRow.InterfaceLuid);
        ipRow.Family = AF_INET;
        ipRow.NlMtu = mtu;
        DWORD ret = SetIpInterfaceEntry(&ipRow);
        if (ret == NO_ERROR)
        {
            tuntap->mtu4 = mtu;
        }
        else
        {
            raise_error_from_errno();
        }
    }
    return 0;
}

static PyObject* wintun_get_mtu6(PyObject* self, void* d) {
    wintun_t* tuntap = (wintun_t*)self;
    return PyLong_FromLong(tuntap->mtu6);
}

static int wintun_set_mtu6(PyObject* self, PyObject* value, void* d) {
    wintun_t* tuntap = (wintun_t*)self;
    MTU_INIT
    if (mtu != tuntap->mtu4) {
        MIB_IPINTERFACE_ROW ipRow;
        InitializeIpInterfaceEntry(&ipRow);
        WintunGetAdapterLUID(tuntap->adapter, &ipRow.InterfaceLuid);
        ipRow.Family = AF_INET6;
        ipRow.NlMtu = mtu;
        DWORD ret = SetIpInterfaceEntry(&ipRow);
        if (ret == NO_ERROR)
        {
            tuntap->mtu4 = mtu;
        }
        else
        {
            raise_error_from_errno();
        }
    }
    return 0;
}

#define UNICAST_IP_ADDR_INIT                                            \
    wintun_t* tuntap = (wintun_t*)self;                                 \
    wchar_t strAddr[256] = { 0 };                                       \
    int len = PyUnicode_AsWideChar(value, strAddr, 256);                \
    DWORD LastError = 0;                                                \
    MIB_UNICASTIPADDRESS_ROW AddressRow;                                \
    InitializeUnicastIpAddressEntry(&AddressRow);                       \
    WintunGetAdapterLUID(tuntap->adapter, &AddressRow.InterfaceLuid);   \
    PWCHAR  Terminator;

static int wintun_set_addr6(PyObject* self, PyObject* value, void* d) {
    UNICAST_IP_ADDR_INIT
    if (NT_SUCCESS(RtlIpv6StringToAddressW(
        strAddr,
        &Terminator,
        &AddressRow.Address.Ipv6.sin6_addr
    )))
    {
        AddressRow.Address.Ipv6.sin6_family = AF_INET6;
        AddressRow.OnLinkPrefixLength = 64; /* This is a /64 network */
        tuntap->proto_bits |= 2;
        goto done;

    }
done:
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        raise_error("Failed to set IPv6 address");
    }
    else
    {
        wcscpy_s(tuntap->addr6, 256, strAddr);
    }
    return 0;
}

static PyObject* wintun_get_addr6(PyObject* self, void* d) {
    wintun_t* tuntap = (wintun_t*)self;
    return PyUnicode_FromWideChar(tuntap->addr6, -1);
}

static int wintun_set_addr4(PyObject* self, PyObject* value, void* d) {
    UNICAST_IP_ADDR_INIT
    if (NT_SUCCESS(RtlIpv4StringToAddressW(
        strAddr,
        FALSE,
        &Terminator,
        &AddressRow.Address.Ipv4.sin_addr
    )))
    {
        AddressRow.Address.Ipv4.sin_family = AF_INET;
        AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
        tuntap->proto_bits |= 1;
        goto done;
    }
done:
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        raise_error("Failed to set IPv4 address");
    }
    else
    {
        wcscpy_s(tuntap->addr4, 32, strAddr);
    }
    return 0;
}

static PyObject* wintun_get_addr4(PyObject* self, void* d) {
    wintun_t* tuntap = (wintun_t*)self;
    return PyUnicode_FromWideChar(tuntap->addr4, -1);
}

static PyGetSetDef wintun_prop[] = { { "read_wait_event", wintun_readwait_event, NULL, NULL, NULL },
                                     { "name", wintun_get_name, NULL, NULL, NULL },
                                     { "ring_capacity", wintun_get_capacity, wintun_set_capacity, NULL, NULL },
                                     { "addr", wintun_get_addr6, wintun_set_addr6, NULL, NULL },
                                     { "addr4", wintun_get_addr4, wintun_set_addr4, NULL, NULL },
                                     { "mtu", wintun_get_mtu6, wintun_set_mtu6, NULL, NULL },
                                     { "mtu4", wintun_get_mtu4, wintun_set_mtu4, NULL, NULL },
                                     { NULL, NULL, NULL, NULL, NULL } };

PyDoc_STRVAR(wintun_doc, "TunDevice(name='', type='', capacity=0x40000, proto_aware=True) -> create TUN device object. When proto_aware is True, only send the packets that match adapter's protocol.");

/* Define PyVarObject_HEAD_INIT for python 2.5 */
#    ifndef PyVarObject_HEAD_INIT
#        define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(type) size,
#    endif

static PyTypeObject wintun_type = { PyVarObject_HEAD_INIT(NULL, 0)
                                    .tp_name = "wintun.TunDevice",
                                    .tp_basicsize = sizeof(wintun_t),
                                    .tp_dealloc = wintun_dealloc,
                                    .tp_flags = Py_TPFLAGS_DEFAULT,
                                    .tp_doc = wintun_doc,
                                    .tp_methods = wintun_meth,
                                    .tp_getset = wintun_prop,
                                    .tp_new = wintun_new };

static PyObject *
py_get_driver_version(PyObject *self, PyObject *args)
{
    return Py_BuildValue("i", WintunGetRunningDriverVersion());
}

static PyObject *gLogCallback = NULL;
static void
_logCallback(WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message)
{
    if (gLogCallback)
    {
        PyGILState_STATE gstate= PyGILState_Ensure();
        PyObject* mesage = PyUnicode_FromWideChar(Message,  -1);
        PyObject *result = PyEval_CallFunction(gLogCallback, "iKO", Level, Timestamp, mesage);
        PyGILState_Release(gstate);
    }
}

static PyObject *
py_set_logger(PyObject *self, PyObject *args)
{
    PyObject *callback = NULL;
    if (!PyArg_ParseTuple(args, "O", &callback))
    {
        return NULL;
    }
    if (callback != gLogCallback)
    {
        //if (gLogCallback)
        //{
        //    Py_DECREF(gLogCallback);
        //    gLogCallback = NULL;
        //}
        gLogCallback = callback;
        //Py_INCREF(callback);
    }
    WintunSetLogger(_logCallback);
    Py_RETURN_NONE;
}

static PyObject*
py_install_wetest_driver(PyObject* self, PyObject* args)
{
    InstallWeTestDriver();
    Py_RETURN_NONE;
}

static PyObject*
py_uninstall_wetest_driver(PyObject* self, PyObject* args)
{
    UninstallWeTestDriver();
    Py_RETURN_NONE;
}

static PyObject*
py_check_wetest_driver_status(PyObject* self, PyObject* args)
{
    BOOL    Exists[] = { FALSE, FALSE };
    BOOL    Expired[] = { FALSE, FALSE };
    CheckWetestDriverStatus(Exists, Expired);
    return Py_BuildValue("[(OO),(OO)]", 
        Exists[0] ? Py_True: Py_False, Expired[0] ? Py_True : Py_False, 
        Exists[1] ? Py_True : Py_False, Expired[1] ? Py_True : Py_False
    );
}

static PyObject *
py_delete_driver(PyObject *self, PyObject *args)
{
    return Py_BuildValue("i", WintunDeleteDriver());
}

/* Module method table */
static struct PyMethodDef wintunMethods[] = {
    { "get_driver_version", py_get_driver_version, METH_VARARGS, "Get running driver version" },
    { "set_logger", py_set_logger, METH_VARARGS, "Set logger" },
    { "delete_driver", py_delete_driver, METH_VARARGS, "Delete driver" },
    { "install_wetest_driver", py_install_wetest_driver, METH_VARARGS, "Install Wetest driver" },
    { "uninstall_wetest_driver", py_uninstall_wetest_driver, METH_VARARGS, "Uninstall Wetest driver" },
    { "check_wetest_driver_status", py_check_wetest_driver_status, METH_VARARGS, "Check Wetest driver status" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef pytun_module = { .m_base = PyModuleDef_HEAD_INIT,
                                           .m_name = "pywintunx_pmd3",
                                           .m_doc = NULL,
                                           .m_size = -1,
                                           .m_methods = wintunMethods,
#if PY_MINOR_VERSION <= 4
                                           .m_reload = NULL,
#else
                                           .m_slots = NULL,
#endif
                                           .m_traverse = NULL,
                                           .m_clear = NULL,
                                           .m_free = NULL };
#endif

/* Module initialization function */
#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC
PyInit_pywintunx_pmd3(void)
#else
PyMODINIT_FUNC
initpywintunx_pmd3(void)
#endif
{
    PyObject *m;
    PyObject* pytun_error_dict = NULL;
#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&pytun_module);
#else
    m = Py_InitModule("pywintunx_pmd3", NULL);
#endif
    if (PyType_Ready(&wintun_type) != 0)
    {
        // goto error;
    }
    
    pytun_error_dict = Py_BuildValue("{ss}", "__doc__", wintun_error_doc);
    if (pytun_error_dict == NULL)
    {
        goto error;
    }
    py_wintun_error = PyErr_NewException("pywintunx_pmd3.Error", PyExc_IOError, pytun_error_dict);
    Py_DECREF(pytun_error_dict);
    if (py_wintun_error == NULL)
    {
        goto error;
    }
    Py_INCREF(py_wintun_error);
    if (PyModule_AddObject(m, "Error", py_wintun_error) != 0)
    {
        Py_DECREF(py_wintun_error);
        goto error;
    }

    Py_INCREF((PyObject *)&wintun_type);
    if (PyModule_AddObject(m, "TunTapDevice", (PyObject *)&wintun_type) != 0)
    {
        Py_DECREF((PyObject *)&wintun_type);
        // goto error;
    }
error:
    return m;
}

#endif