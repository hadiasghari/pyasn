/*
 * Portions Copyright (c) 2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

 /*
 * Portions Copyright (c) 2014 Michael J. Schultz <mjschultz@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

 /*
   Portions Copyright (c) 2014-2017 Hadi Asghari
   See LICENSE file
 */


#include "Python.h"
#include "structmember.h"
#include "_radix/radix.h"


/* $Id$ */

/* for Py3K */
#if PY_MAJOR_VERSION >= 3
# define PyInt_FromLong                 PyLong_FromLong
# define PyString_FromString            PyUnicode_FromString
# define PyString_FromStringAndSize     PyBytes_FromStringAndSize
#endif

/* for version before 2.6 */
#ifndef PyVarObject_HEAD_INIT
# define PyVarObject_HEAD_INIT(type, size)      PyObject_HEAD_INIT(type) size,
#endif
#ifndef Py_TYPE
# define Py_TYPE(ob)    (((PyObject*)(ob))->ob_type)
#endif

/* Prototypes */
struct _RadixObject;
struct _RadixIterObject;
static struct _RadixIterObject *newRadixIterObject(struct _RadixObject *);
static PyObject *radix_Radix(PyObject *, PyObject *);

/* ------------------------------------------------------------------------ */

PyObject *radix_constructor;

/* RadixNode: tree nodes */

typedef struct {
        PyObject_HEAD
        u_int32_t asn;
        radix_node_t *rn;       /* Actual radix node (pointer to parent) */
} RadixNodeObject;

static PyTypeObject RadixNode_Type;

static RadixNodeObject *
newRadixNodeObject(radix_node_t *rn)
{
        RadixNodeObject *self;

        /* Sanity check */
        if (rn == NULL || rn->prefix == NULL ||
            (rn->prefix->family != AF_INET && rn->prefix->family != AF_INET6))
                return NULL;

        self = PyObject_New(RadixNodeObject, &RadixNode_Type);
        if (self == NULL)
                return NULL;

        self->rn = rn;
        self->asn = 0;

        return self;
}

/* RadixNode methods */

static void
RadixNode_dealloc(RadixNodeObject *self)
{
        PyObject_Del(self);
}


static PyObject *
_get_prefix(radix_node_t *rn) {
    PyObject *ret;
    char addr[INET6_ADDRSTRLEN], buf[128];
    if (rn->prefix == NULL)
        return NULL;
    if (inet_ntop(rn->prefix->family, &rn->prefix->add, addr, sizeof(addr)) == NULL)
        return NULL;
    sprintf(buf, "%s/%d", addr, rn->prefix->bitlen);
    ret = PyString_FromString(buf);
    return ret;
}


static PyObject *
RadixNode_getprefix(RadixNodeObject *self, void *closure)
{
    return _get_prefix(self->rn);
}


static PyObject *
RadixNode_getasn(RadixNodeObject *self, void *closure)
{
    return PyInt_FromLong(self->asn);
}


static int
RadixNode_setasn(RadixNodeObject *self, PyObject *value, void* clsoure)
{
    u_int32_t val;
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the ASN attribute");
        return -1;
    }
    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The ASN attribute value must be an integer");
        return -1;
    }
    val = (u_int32_t) PyLong_AsUnsignedLong(value);
    self->asn = val;
    return 0;
}


static PyGetSetDef RadixNode_getseters[] = {
    {"prefix",  (getter)RadixNode_getprefix, NULL,                     "full prefix matching the searched IP in the BGP table",   NULL},
    {"asn",     (getter)RadixNode_getasn,    (setter)RadixNode_setasn, "autonomous system number that has advertised (and 'holds') this prefix",  NULL},
    {NULL}  /* Sentinel */
};



PyDoc_STRVAR(RadixNode_doc,
"Node in a radix tree");

static PyTypeObject RadixNode_Type = {
        /* The ob_type field must be initialized in the module init function
         * to be portable to Windows without using C++. */
        PyVarObject_HEAD_INIT(NULL, 0)
        "pyasn_radix.RadixNode",      /*tp_name*/
        sizeof(RadixNodeObject),/*tp_basicsize*/
        0,                      /*tp_itemsize*/
        /* methods */
        (destructor)RadixNode_dealloc, /*tp_dealloc*/
        0,                      /*tp_print*/
        0,                      /*tp_getattr*/
        0,                      /*tp_setattr*/
        0,                      /*tp_compare*/
        0,                      /*tp_repr*/
        0,                      /*tp_as_number*/
        0,                      /*tp_as_sequence*/
        0,                      /*tp_as_mapping*/
        0,                      /*tp_hash*/
        0,                      /*tp_call*/
        0,                      /*tp_str*/
        0,                      /*tp_getattro*/
        0,                      /*tp_setattro*/
        0,                      /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT,     /*tp_flags*/
        RadixNode_doc,          /*tp_doc*/
        0,                      /*tp_traverse*/
        0,                      /*tp_clear*/
        0,                      /*tp_richcompare*/
        0,                      /*tp_weaklistoffset*/
        0,                      /*tp_iter*/
        0,                      /*tp_iternext*/
        0,                      /*tp_methods*/
        0,                      /*tp_members*/
        RadixNode_getseters,    /*tp_getset*/
        0,                      /*tp_base*/
        0,                      /*tp_dict*/
        0,                      /*tp_descr_get*/
        0,                      /*tp_descr_set*/
        0,                      /*tp_dictoffset*/
        0,                      /*tp_init*/
        0,                      /*tp_alloc*/
        0,                      /*tp_new*/
        0,                      /*tp_free*/
        0,                      /*tp_is_gc*/
};


/* ------------------------------------------------------------------------ */

typedef struct _RadixObject {
        PyObject_HEAD
        radix_tree_t *rt4;      /* Radix tree for IPv4 addresses */
        radix_tree_t *rt6;      /* Radix tree for IPv6 addresses */
        unsigned int gen_id;    /* Detect modification during iterations */
} RadixObject;

static PyTypeObject Radix_Type;
#define Radix_CheckExact(op) (Py_TYPE(op) == &Radix_Type)

static RadixObject *
newRadixObject(void)
{
        RadixObject *self;
        radix_tree_t *rt4, *rt6;

        if ((rt4 = New_Radix()) == NULL)
                return (NULL);
        if ((rt6 = New_Radix()) == NULL) {
                free(rt4);
                return (NULL);
        }
        if ((self = PyObject_New(RadixObject, &Radix_Type)) == NULL) {
                free(rt4);
                free(rt6);
                return (NULL);
        }
        self->rt4 = rt4;
        self->rt6 = rt6;
        self->gen_id = 0;
        return (self);
}

/* Radix methods */

static void
Radix_dealloc(RadixObject *self)
{
        radix_node_t *rn;
        RadixNodeObject *node;

        RADIX_WALK(self->rt4->head, rn) {
                if (rn->data != NULL) {
                        node = rn->data;
                        node->rn = NULL;
                        Py_DECREF(node);
                }
        } RADIX_WALK_END;
        RADIX_WALK(self->rt6->head, rn) {
                if (rn->data != NULL) {
                        node = rn->data;
                        node->rn = NULL;
                        Py_DECREF(node);
                }
        } RADIX_WALK_END;

        Destroy_Radix(self->rt4, NULL, NULL);
        Destroy_Radix(self->rt6, NULL, NULL);
        PyObject_Del(self);
}

static prefix_t
*args_to_prefix(char *addr, char *packed, int packlen, long prefixlen)
{
        prefix_t *prefix = NULL;
        const char *errmsg;

        if (addr != NULL && packed != NULL) {
                PyErr_SetString(PyExc_TypeError, "Two address types specified. Please pick one.");
                return NULL;
        }
        if (addr == NULL && packed == NULL) {
                PyErr_SetString(PyExc_TypeError, "No address specified");
                return NULL;
        }
        if (addr != NULL) {             /* Parse a string address */
                if ((prefix = prefix_pton(addr, prefixlen, &errmsg)) == NULL) {
					PyErr_SetString(PyExc_ValueError, errmsg ? errmsg : "Invalid address format");
                }
        } else if (packed != NULL) {    /* "parse" a packed binary address */
                if ((prefix = prefix_from_blob((u_char*)packed, packlen, prefixlen)) == NULL) {
                        PyErr_SetString(PyExc_ValueError, "Invalid packed address format");
                }
        }
        if (prefix != NULL &&
            prefix->family != AF_INET && prefix->family != AF_INET6) {
                Deref_Prefix(prefix);
                return (NULL);
        }
        return prefix;
}

#define PICKRT(prefix, rno) (prefix->family == AF_INET6 ? rno->rt6 : rno->rt4)

static PyObject *
create_add_node(RadixObject *self, prefix_t *prefix)
{
        radix_node_t *node;
        RadixNodeObject *node_obj;

        if ((node = radix_lookup(PICKRT(prefix, self), prefix)) == NULL) {
                PyErr_SetString(PyExc_MemoryError, "Couldn't add prefix");
                return NULL;
        }

        /*
         * Create a RadixNode object in the data area of the node
         * We duplicate most of the node's identity, because the radix.c:node
         * itself has a lifetime independent of the Python node object
         * Confusing? yeah...
         */
        if (node->data == NULL) {
                if ((node_obj = newRadixNodeObject(node)) == NULL)
                        return (NULL);
                node->data = node_obj;
        } else
                node_obj = node->data;

        self->gen_id++;
        Py_XINCREF(node_obj);
        return (PyObject *)node_obj;
}



PyDoc_STRVAR(Radix_add_doc,
"Radix.add(network[, masklen][, packed]) -> new RadixNode object\n\
\n\
Adds the network specified by 'network' and 'masklen' to the radix\n\
tree. 'network' may be a string in CIDR format, a unicast host\n\
address or a network address, with the mask length specified using\n\
the optional 'masklen' parameter.\n\
\n\
Alternately, the address may be specified in a packed binary format\n\
using the 'packed' keyword argument (instead of 'network'). This is\n\
useful with binary addresses returned by socket.getpeername(),\n\
socket.inet_ntoa(), etc.\n\
\n\
Both IPv4 and IPv6 addresses/networks are supported and may be mixed in\n\
the same tree.\n\
\n\
This method returns a RadixNode object. Arbitrary data may be stored\n\
in the RadixNode.data dict.");

static PyObject *
Radix_add(RadixObject *self, PyObject *args, PyObject *kw_args)
{
        prefix_t *prefix;
        static char *keywords[] = { "network", "masklen", "packed", NULL };
        PyObject *node_obj;

        char *addr = NULL, *packed = NULL;
        long prefixlen = -1;
        int packlen = -1;

        if (!PyArg_ParseTupleAndKeywords(args, kw_args, "|sls#:add", keywords,
            &addr, &prefixlen, &packed, &packlen))
                return NULL;
        if ((prefix = args_to_prefix(addr, packed, packlen, prefixlen)) == NULL)
                return NULL;

        node_obj = create_add_node(self, prefix);
        Deref_Prefix(prefix);

        return node_obj;
}

PyDoc_STRVAR(Radix_delete_doc,
"Radix.delete(network[, masklen][, packed] -> None\n\
\n\
Deletes the specified network from the radix tree.");

static PyObject *
Radix_delete(RadixObject *self, PyObject *args, PyObject *kw_args)
{
        radix_node_t *node;
        RadixNodeObject *node_obj;
        prefix_t *prefix;
        static char *keywords[] = { "network", "masklen", "packed", NULL };

        char *addr = NULL, *packed = NULL;
        long prefixlen = -1;
        int packlen = -1;

        if (!PyArg_ParseTupleAndKeywords(args, kw_args, "|sls#:delete", keywords,
            &addr, &prefixlen, &packed, &packlen))
                return NULL;
        if ((prefix = args_to_prefix(addr, packed, packlen, prefixlen)) == NULL)
                return NULL;
        if ((node = radix_search_exact(PICKRT(prefix, self), prefix)) == NULL) {
                Deref_Prefix(prefix);
                PyErr_SetString(PyExc_KeyError, "no such address");
                return NULL;
        }
        if (node->data != NULL) {
                node_obj = node->data;
                node_obj->rn = NULL;
                Py_XDECREF(node_obj);
        }

        radix_remove(PICKRT(prefix, self), node);
        Deref_Prefix(prefix);

        self->gen_id++;
        Py_INCREF(Py_None);
        return Py_None;
}

PyDoc_STRVAR(Radix_search_exact_doc,
"Radix.search_exact(network[, masklen][, packed] -> RadixNode or None\n\
\n\
Search for the specified network in the radix tree. In order to\n\
match, the 'prefix' must be specified exactly. Contrast with the\n\
Radix.search_best method.\n\
\n\
If no match is found, then this method returns None.");

static PyObject *
Radix_search_exact(RadixObject *self, PyObject *args, PyObject *kw_args)
{
        radix_node_t *node;
        RadixNodeObject *node_obj;
        prefix_t *prefix;
        static char *keywords[] = { "network", "masklen", "packed", NULL };

        char *addr = NULL, *packed = NULL;
        long prefixlen = -1;
        int packlen = -1;

        if (!PyArg_ParseTupleAndKeywords(args, kw_args, "|sls#:search_exact", keywords,
            &addr, &prefixlen, &packed, &packlen))
                return NULL;
        if ((prefix = args_to_prefix(addr, packed, packlen, prefixlen)) == NULL)
                return NULL;

        node = radix_search_exact(PICKRT(prefix, self), prefix);
        if (node == NULL || node->data == NULL) {
                Deref_Prefix(prefix);
                Py_INCREF(Py_None);
                return Py_None;
        }
        Deref_Prefix(prefix);
        node_obj = node->data;
        Py_XINCREF(node_obj);
        return (PyObject *)node_obj;
}

PyDoc_STRVAR(Radix_search_best_doc,
"Radix.search_best(network[, masklen][, packed] -> None\n\
\n\
Search for the specified network in the radix tree.\n\
\n\
search_best will return the best (longest) entry that includes the\n\
specified 'prefix', much like a IP routing table lookup.\n\
\n\
If no match is found, then returns None.");

static PyObject *
Radix_search_best(RadixObject *self, PyObject *args, PyObject *kw_args)
{
        radix_node_t *node;
        RadixNodeObject *node_obj;
        prefix_t *prefix;
        static char *keywords[] = { "network", "masklen", "packed", NULL };

        char *addr = NULL, *packed = NULL;
        long prefixlen = -1;
        int packlen = -1;

        if (!PyArg_ParseTupleAndKeywords(args, kw_args, "|sls#:search_best", keywords,
            &addr, &prefixlen, &packed, &packlen))
                return NULL;
        if ((prefix = args_to_prefix(addr, packed, packlen, prefixlen)) == NULL)
                return NULL;

        if ((node = radix_search_best(PICKRT(prefix, self), prefix)) == NULL ||
            node->data == NULL) {
                Deref_Prefix(prefix);
                Py_INCREF(Py_None);
                return Py_None;
        }
        Deref_Prefix(prefix);
        node_obj = node->data;
        Py_XINCREF(node_obj);
        return (PyObject *)node_obj;
}

PyDoc_STRVAR(Radix_nodes_doc,
"Radix.nodes(prefix) -> List of RadixNode\n\
\n\
Returns a list containing all the RadixNode objects that have been\n\
entered into the tree. This list may be empty if no prefixes have\n\
been entered.");

static PyObject *
Radix_nodes(RadixObject *self, PyObject *args)
{
        radix_node_t *node;
        PyObject *ret;

        if (!PyArg_ParseTuple(args, ":nodes"))
                return NULL;

        if ((ret = PyList_New(0)) == NULL)
                return NULL;

        RADIX_WALK(self->rt4->head, node) {
                if (node->data != NULL)
                        PyList_Append(ret, (PyObject *)node->data);
        } RADIX_WALK_END;
        RADIX_WALK(self->rt6->head, node) {
                if (node->data != NULL)
                        PyList_Append(ret, (PyObject *)node->data);
        } RADIX_WALK_END;

        return (ret);
}

PyDoc_STRVAR(Radix_prefixes_doc,
"Radix.prefixes(prefix) -> List of prefix strings\n\
\n\
Returns a list containing all the prefixes that have been entered\n\
into the tree. This list may be empty if no prefixes have been\n\
entered.");

static PyObject *
Radix_prefixes(RadixObject *self, PyObject *args)
{
        radix_node_t *node;
        PyObject *ret, *prefix;

        if (!PyArg_ParseTuple(args, ":prefixes"))
                return NULL;

        if ((ret = PyList_New(0)) == NULL)
                return NULL;

        RADIX_WALK(self->rt4->head, node) {
                if (node->data != NULL) {
                        prefix = _get_prefix(node); // if NULL?
                        PyList_Append(ret, prefix);
                        Py_XDECREF(prefix); // PyList_Append doesn't "steal" the ref; so we need to release ours
                }
        } RADIX_WALK_END;
        RADIX_WALK(self->rt6->head, node) {
                if (node->data != NULL) {
                        prefix = _get_prefix(node);
                        PyList_Append(ret, prefix);
                        Py_XDECREF(prefix);
                }
        } RADIX_WALK_END;

        return (ret);
}


/* ------------------------------------------------------------------------ */
// ADDED BY HADI


prefix_t *
convert_to_prefix_v4(void *addr, int bitlen)
{
    prefix_t *prefix = NULL;
    if ((prefix = PyMem_Malloc(sizeof(*prefix))) == NULL)
        return NULL;
    memset(prefix, '\0', sizeof(*prefix));
    memcpy(&prefix->add.sin, addr, 4);
    prefix->bitlen = bitlen;
    prefix->family = AF_INET;
    prefix->ref_count = 1;
    return prefix;
}

static int
add_pyobject_to_radix_tree(RadixObject *self, u_int32_t asn, u_int8_t prefixlen, const char *net_addr)
{
    // new method, 2017-01-05, refactoring Radix_load_ipasndb()
    const char *err_msg_i = "";
    PyObject *node_obj = NULL;
    prefix_t *prefix = NULL;

    if (asn == 0 || prefixlen == 0)
        return 0;

    if ((prefix = prefix_pton(net_addr, prefixlen, &err_msg_i)) == NULL)  // works with IPv4 and IPv6 addresses
        return 0;

    if ((node_obj = create_add_node(self, prefix)) == NULL)
        return 0;

    ((RadixNodeObject *)node_obj)->asn = asn;

    Py_DECREF(node_obj);
    Deref_Prefix(prefix);
    return 1;
}


PyDoc_STRVAR(Radix_load_ipasndb_doc,
"Radix.load_ipasndb(from_file, from_string) -> number_records\n\
\n\
Loads an IP-ASN-database into the RADIX tree.\n\
It can read it from a text file (with fields: prefix/mask asn),\n\
or from a string with the same fileds.\n\
\n\
Notes:\n\
- There are helper scripts to make the IPASN databases\n\
- The tree must be empty before calling this function.\n\
- The text file supports both IPv4 & IPv6.");


static PyObject *
Radix_load_ipasndb(RadixObject *self, PyObject *args, PyObject *kw_args)
{
    static char *keywords[] = { "from_file", "from_string", NULL };
    const char *from_file = NULL, *from_string = NULL;
    char use_file, use_string;
  	FILE* ccfd = NULL;
  	size_t record = 0;
    char err_msg[512];

    if (!PyArg_ParseTupleAndKeywords(args, kw_args, "s|s:load_ipasn",  keywords, &from_file, &from_string))
      return NULL;  // FIXME: we want to accept 'None' for either parameter too

    use_file = (from_file != NULL && *from_file);
    use_string = (from_string != NULL && *from_string);

    if ((use_file && use_string) || (!use_file && !use_string)) {
          PyErr_SetString(PyExc_RuntimeError, "load_ipasndb() needs one of from_file/from_string.");
          return NULL;
    }

    if (self->rt4->head != NULL || self->rt6->head != NULL) {
          PyErr_SetString(PyExc_RuntimeError, "load_ipasndb() called on non-empty radix-tree");
          return NULL;
    }

    if (use_file)
    {
	char buf[512], *p1, *p2;    
        // Construct radix-tree from file
        if ((ccfd = fopen(from_file, "rt" )) == NULL) {
            PyErr_SetString(PyExc_IOError, "Could not open the file.");
            return NULL;
        }

        while (fgets(buf, 512, ccfd) != NULL)  {

            if (buf[0] == ';' || buf[0] == '#' || buf[0] == '\n' || buf[0] == 0)
                continue;  // skip comments and empty lines

            if ( (p1=strchr(buf, '\t')) == NULL || (p2 = strchr(buf, '/')) == NULL || p2>p1 )
                goto parse_or_memory_error;

            *p1++ = *p2++ = 0;  // now: p1 is ASN; p2 is PrefixLen; buf is network address

            if (!add_pyobject_to_radix_tree(self, atol(p1), atoi(p2), buf))
                goto parse_or_memory_error;

            record++;
        }

        fclose(ccfd);
  }
  else {
        // Construct radix tree from string
        const char *head = from_string;
        char buf[512], *p1, *p2;

        while (*head)  {
            int k = 0;

            while (*head && *head != '\n') {
              buf[k++] = *head++;
              if (k > 500)
                goto parse_or_memory_error; // line is too big
            }
            if (*head=='\n')
              head++;
            buf[k] = 0;

            if (buf[0] == ';' || buf[0] == '#' || buf[0] == '\n' || buf[0]==0)
                continue;  // skip comments and empty lines

            if ( (p1=strchr(buf, '\t')) == NULL || (p2 = strchr(buf, '/')) == NULL || p2>p1 )
                goto parse_or_memory_error;

            *p1++ = *p2++ = 0;  // now: p1 is ASN; p2 is PrefixLen; buf is network address

            if (!add_pyobject_to_radix_tree(self, atol(p1), atoi(p2), buf))
                goto parse_or_memory_error;

            record++;
        }
    }

    return PyInt_FromLong(record);

parse_or_memory_error:

    sprintf(err_msg, "Error while parsing/adding IPASN database (record: %d)!", (int)(record+1));
    PyErr_SetString(PyExc_RuntimeError, err_msg);
    if (ccfd)
      fclose(ccfd);
    return NULL;
}

/* ------------------------------------------------------------------------ */

static PyObject *
Radix_getiter(RadixObject *self)
{
        return (PyObject *)newRadixIterObject(self);
}

PyDoc_STRVAR(Radix_doc, "Radix tree");

static PyMethodDef Radix_methods[] = {
        {"add",         (PyCFunction)Radix_add,         METH_VARARGS|METH_KEYWORDS,     Radix_add_doc           },
        {"delete",      (PyCFunction)Radix_delete,      METH_VARARGS|METH_KEYWORDS,     Radix_delete_doc        },
        {"search_exact",(PyCFunction)Radix_search_exact,METH_VARARGS|METH_KEYWORDS,     Radix_search_exact_doc  },
        {"search_best", (PyCFunction)Radix_search_best, METH_VARARGS|METH_KEYWORDS,     Radix_search_best_doc   },
        {"nodes",       (PyCFunction)Radix_nodes,       METH_VARARGS,                   Radix_nodes_doc         },
        {"prefixes",    (PyCFunction)Radix_prefixes,    METH_VARARGS,                   Radix_prefixes_doc      },
        {"load_ipasndb",(PyCFunction)Radix_load_ipasndb,METH_VARARGS|METH_KEYWORDS, 	Radix_load_ipasndb_doc  },
        {NULL,          NULL}           /* sentinel */
};

static PyTypeObject Radix_Type = {
        /* The ob_type field must be initialized in the module init function
         * to be portable to Windows without using C++. */
        PyVarObject_HEAD_INIT(NULL, 0)
        "pyasn_radix.Radix",          /*tp_name*/
        sizeof(RadixObject),    /*tp_basicsize*/
        0,                      /*tp_itemsize*/
        /* methods */
        (destructor)Radix_dealloc, /*tp_dealloc*/
        0,                      /*tp_print*/
        0,                      /*tp_getattr*/
        0,                      /*tp_setattr*/
        0,                      /*tp_compare*/
        0,                      /*tp_repr*/
        0,                      /*tp_as_number*/
        0,                      /*tp_as_sequence*/
        0,                      /*tp_as_mapping*/
        0,                      /*tp_hash*/
        0,                      /*tp_call*/
        0,                      /*tp_str*/
        0,                      /*tp_getattro*/
        0,                      /*tp_setattro*/
        0,                      /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT,     /*tp_flags*/
        Radix_doc,              /*tp_doc*/
        0,                      /*tp_traverse*/
        0,                      /*tp_clear*/
        0,                      /*tp_richcompare*/
        0,                      /*tp_weaklistoffset*/
        (getiterfunc)Radix_getiter, /*tp_iter*/
        0,                      /*tp_iternext*/
        Radix_methods,          /*tp_methods*/
        0,                      /*tp_members*/
        0,                      /*tp_getset*/
        0,                      /*tp_base*/
        0,                      /*tp_dict*/
        0,                      /*tp_descr_get*/
        0,                      /*tp_descr_set*/
        0,                      /*tp_dictoffset*/
        0,                      /*tp_init*/
        0,                      /*tp_alloc*/
        0,                      /*tp_new*/
        0,                      /*tp_free*/
        0,                      /*tp_is_gc*/
};

/* ------------------------------------------------------------------------ */

/* RadixIter: radix tree iterator */

typedef struct _RadixIterObject {
        PyObject_HEAD
        RadixObject *parent;
        radix_node_t *iterstack[RADIX_MAXBITS+1];
        radix_node_t **sp;
        radix_node_t *rn;
        int af;
        unsigned int gen_id;    /* Detect tree modifications */
} RadixIterObject;

static PyTypeObject RadixIter_Type;

static RadixIterObject *
newRadixIterObject(RadixObject *parent)
{
        RadixIterObject *self;

        self = PyObject_New(RadixIterObject, &RadixIter_Type);
        if (self == NULL)
                return NULL;

        self->parent = parent;
        Py_XINCREF(self->parent);

        self->sp = self->iterstack;
        self->rn = self->parent->rt4->head;
        self->gen_id = self->parent->gen_id;
        self->af = AF_INET;
        return self;
}

/* RadixIter methods */

static void
RadixIter_dealloc(RadixIterObject *self)
{
        Py_XDECREF(self->parent);
        PyObject_Del(self);
}

static PyObject *
RadixIter_iternext(RadixIterObject *self)
{
        radix_node_t *node;
        PyObject *ret;

        if (self->gen_id != self->parent->gen_id) {
                PyErr_SetString(PyExc_RuntimeWarning,
                    "Radix tree modified during iteration");
                return (NULL);
        }

 again:
        if ((node = self->rn) == NULL) {
                /* We have walked both trees */
                if (self->af == AF_INET6)
                        return NULL;
                /* Otherwise reset and start walk of IPv6 tree */
                self->sp = self->iterstack;
                self->rn = self->parent->rt6->head;
                self->af = AF_INET6;
                goto again;
        }

        /* Get next node */
        if (self->rn->l) {
                if (self->rn->r)
                        *self->sp++ = self->rn->r;
                self->rn = self->rn->l;
        } else if (self->rn->r)
                self->rn = self->rn->r;
        else if (self->sp != self->iterstack)
                self->rn = *(--self->sp);
        else
                self->rn = NULL;

        if (node->prefix == NULL || node->data == NULL)
                goto again;

        ret = node->data;
        Py_INCREF(ret);
        return (ret);
}

PyDoc_STRVAR(RadixIter_doc,
"Radix tree iterator");

static PyTypeObject RadixIter_Type = {
        /* The ob_type field must be initialized in the module init function
         * to be portable to Windows without using C++. */
        PyVarObject_HEAD_INIT(NULL, 0)
        "pyasn_radix.RadixIter",      /*tp_name*/
        sizeof(RadixIterObject),/*tp_basicsize*/
        0,                      /*tp_itemsize*/
        /* methods */
        (destructor)RadixIter_dealloc, /*tp_dealloc*/
        0,                      /*tp_print*/
        0,                      /*tp_getattr*/
        0,                      /*tp_setattr*/
        0,                      /*tp_compare*/
        0,                      /*tp_repr*/
        0,                      /*tp_as_number*/
        0,                      /*tp_as_sequence*/
        0,                      /*tp_as_mapping*/
        0,                      /*tp_hash*/
        0,                      /*tp_call*/
        0,                      /*tp_str*/
        0,                      /*tp_getattro*/
        0,                      /*tp_setattro*/
        0,                      /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT,     /*tp_flags*/
        RadixIter_doc,          /*tp_doc*/
        0,                      /*tp_traverse*/
        0,                      /*tp_clear*/
        0,                      /*tp_richcompare*/
        0,                      /*tp_weaklistoffset*/
        0,                      /*tp_iter*/
        (iternextfunc)RadixIter_iternext, /*tp_iternext*/
        0,                      /*tp_methods*/
        0,                      /*tp_members*/
        0,                      /*tp_getset*/
        0,                      /*tp_base*/
        0,                      /*tp_dict*/
        0,                      /*tp_descr_get*/
        0,                      /*tp_descr_set*/
        0,                      /*tp_dictoffset*/
        0,                      /*tp_init*/
        0,                      /*tp_alloc*/
        0,                      /*tp_new*/
        0,                      /*tp_free*/
        0,                      /*tp_is_gc*/
};

/* ------------------------------------------------------------------------ */

/* Radix object creator */

PyDoc_STRVAR(radix_Radix_doc,
"Radix() -> new Radix tree object\n\
\n\
Instantiate a new radix tree object.");

static PyObject *
radix_Radix(PyObject *self, PyObject *args)
{
        RadixObject *rv;

        if (!PyArg_ParseTuple(args, ":Radix"))
                return NULL;
        rv = newRadixObject();
        if (rv == NULL)
                return NULL;
        return (PyObject *)rv;
}

static PyMethodDef radix_methods[] = {
        {"Radix",       radix_Radix,    METH_VARARGS,   radix_Radix_doc },
        {NULL,          NULL}           /* sentinel */
};

PyDoc_STRVAR(module_doc,
"Implementation of a radix tree data structure for network prefixes.\n"
"\n"
"The radix tree is the data structure most commonly used for routing\n"
"table lookups. It efficiently stores network prefixes of varying\n"
"lengths and allows fast lookups of containing networks.\n"
"\n"
"Simple example:\n"
"\n"
"       import radix\n"
"\n"
"       # Create a new tree\n"
"       rtree = radix.Radix()\n"
"\n"
"       # Adding a node returns a RadixNode object. You can create\n"
"       # arbitrary members in its 'data' dict to store your data\n"
"       rnode = rtree.add(\"10.0.0.0/8\")\n"
"       rnode.data[\"blah\"] = \"whatever you want\"\n"
"\n"
"       # You can specify nodes as CIDR addresses, or networks with\n"
"       # separate mask lengths. The following three invocations are\n"
"       # identical:\n"
"       rnode = rtree.add(\"10.0.0.0/16\")\n"
"       rnode = rtree.add(\"10.0.0.0\", 16)\n"
"       rnode = rtree.add(network = \"10.0.0.0\", masklen = 16)\n"
"\n"
"       # It is also possible to specify nodes using binary packed\n"
"       # addresses, such as those returned by the socket module\n"
"       # functions. In this case, the radix module will assume that\n"
"       # a four-byte address is an IPv4 address and a sixteen-byte\n"
"       # address is an IPv6 address. For example:\n"
"       binary_addr = inet_ntoa(\"172.18.22.0\")\n"
"       rnode = rtree.add(packed = binary_addr, masklen = 23)\n"
"\n"
"       # Exact search will only return prefixes you have entered\n"
"       # You can use all of the above ways to specify the address\n"
"       rnode = rtree.search_exact(\"10.0.0.0/8\")\n"
"       # Get your data back out\n"
"       print rnode.data[\"blah\"]\n"
"       # Use a packed address\n"
"       addr = socket.inet_ntoa(\"10.0.0.0\")\n"
"       rnode = rtree.search_exact(packed = addr, masklen = 8)\n"
"\n"
"       # Best-match search will return the longest matching prefix\n"
"       # that contains the search term (routing-style lookup)\n"
"       rnode = rtree.search_best(\"10.123.45.6\")\n"
"\n"
"       # There are a couple of implicit members of a RadixNode:\n"
"       print rnode.network     # -> \"10.0.0.0\"\n"
"       print rnode.prefix      # -> \"10.0.0.0/8\"\n"
"       print rnode.prefixlen   # -> 8\n"
"       print rnode.family      # -> socket.AF_INET\n"
"       print rnode.packed      # -> '\\n\\x00\\x00\\x00'\n"
"\n"
"       # IPv6 prefixes are fully supported in the same tree\n"
"       rnode = rtree.add(\"2001:DB8::/32\")\n"
"       rnode = rtree.add(\"::/0\")\n"
"\n"
"       # Use the nodes() method to return all RadixNodes created\n"
"       nodes = rtree.nodes()\n"
"       for rnode in nodes:\n"
"               print rnode.prefix\n"
"\n"
"       # The prefixes() method will return all the prefixes (as a\n"
"       # list of strings) that have been entered\n"
"       prefixes = rtree.prefixes()\n"
"\n"
"       # You can also directly iterate over the tree itself\n"
"       # this would save some memory if the tree is big\n"
"       # NB. Don't modify the tree (add or delete nodes) while\n"
"       # iterating otherwise you will abort the iteration and\n"
"       # receive a RuntimeWarning. Changing a node's data dict\n"
"       # is permitted.\n"
"       for rnode in rtree:\n"
"               print rnode.prefix\n"
);

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef radix_module_def = {
    PyModuleDef_HEAD_INIT,
    "pyasn_radix",
    module_doc,
    -1,
    radix_methods,                         // methods
    NULL,                                  // m_reload
    NULL,                                  // traverse
    NULL,                                  // clear
    NULL                                   // free
};
#endif

static PyObject *module_initialize(void)
{
        PyObject *m, *d;

        if (PyType_Ready(&Radix_Type) < 0)
                return NULL;
        if (PyType_Ready(&RadixNode_Type) < 0)
                return NULL;
#if PY_MAJOR_VERSION >= 3
        m = PyModule_Create(&radix_module_def);
#else
        m = Py_InitModule3("pyasn_radix", radix_methods, module_doc);
#endif

        /* Stash the callable constructor for use in Radix.__reduce__ */
        d = PyModule_GetDict(m);
        radix_constructor = PyDict_GetItemString(d, "Radix");

        PyModule_AddIntConstant(m, "__accelerator__", 1);

        return m;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_pyasn_radix(void)
{
        return module_initialize();
}
#else
PyMODINIT_FUNC initpyasn_radix(void)
{
        module_initialize();
}
#endif
