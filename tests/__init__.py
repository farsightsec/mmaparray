'''
MMap Arrays Test Suite

(c) 2014 Farsight Security Inc.

Released under the MIT license.  See license.txt.
'''

import ctypes
import errno
import math
import unittest
import os
import platform
import tempfile
import warnings

import mmaparray
import pkg_resources
import six

_can_populate = platform.system() == 'Linux' and pkg_resources.parse_version(platform.release()) >= pkg_resources.parse_version('2.5.46')

_can_lock = platform.system() == 'Linux' and pkg_resources.parse_version(platform.release()) >= pkg_resources.parse_version('2.5.37')

_can_fallocate = False
libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
if platform.system() == 'Linux' and pkg_resources.parse_version(platform.release()) >= pkg_resources.parse_version('2.6.23'):
    try:
        gnu_get_libc_version = libc.gnu_get_libc_version
        gnu_get_libc_version.restype = ctypes.c_char_p

        libc_version = gnu_get_libc_version()
        if six.PY3:
            libc_version = libc_version.decode('ascii')

        _can_fallocate = pkg_resources.parse_version(libc_version) >= pkg_resources.parse_version('2.10')
    except AttributeError:
        pass

def setUp(typecode, min_val=0, max_val=0, size=1024):
    def fn(self):
        self.backing = tempfile.NamedTemporaryFile(prefix='mmapfile_test')
        self.backing.file.close()

        self.min_val = min_val
        self.max_val = max_val
        self.span = 1 + max_val - min_val
        self.size = size

        self.array = mmaparray.array(self.backing.name, typecode, self.size)
    return fn

class TestMMapArrayGeneric:
    def tearDown(self):
        self.array.close()
        self.backing.close()

    def test_reopen(self):
        array2 = type(self.array)(self.array.name)
        self.assertEqual(len(array2), len(self.array))

    def test_out_of_range(self):
        if self.max_val:
            with self.assertRaises(OverflowError):
                self.array[0] = self.min_val-1
                self.array[0] = self.max_val+1

    def test_out_of_bounds(self):
        with self.assertRaises(OverflowError):
            self.array[-1]
            self.array[-1] = 0

        with self.assertRaises(IndexError):
            self.array[len(self.array)]
            self.array[len(self.array)] = 0

    def test_setgetitem(self):
        self.assertEqual(self.array[0], 0)
        self.array[0] = 1
        self.assertEqual(self.array[0], 1)

        for i in range(1,8):
            self.assertEqual(self.array[i], 0)

        for i in range(1,8):
            self.array[i] = 1
        self.array[0] = 0

        self.assertEqual(self.array[0], 0)
        for i in range(1,8):
            self.assertEqual(self.array[i], 1)

    def test_len(self):
        self.assertEqual(len(self.array), self.size)

    def test_name(self):
        self.assertEqual(self.array.name, six.b(self.backing.name))

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+1) % self.span + self.min_val
        for i, val in enumerate(self.array):
            self.assertEqual((i+1) % self.span + self.min_val, val)

    @unittest.skipUnless(_can_populate, 'MAP_POPULATE not supported on this platform')
    def test_populate(self):
        type(self.array)(self.array.name, want_populate=True)

    @unittest.skipUnless(_can_lock, 'MAP_LOCK not supported on this platform')
    def test_lock(self):
        try:
            type(self.array)(self.array.name, want_lock=True)
        except OSError as e:
            # This can be raised if your ulimit is too low for max locked
            # memory.
            if e.errno == errno.EAGAIN:
                warnings.warn(str(e))
            else:
                raise

    @unittest.skipUnless(_can_fallocate, 'fallocate not supported on this platform')
    def test_fallocate(self):
        try:
            arrayfile = tempfile.NamedTemporaryFile(prefix='mmapfile_test')
            array2 = type(self.array)(arrayfile.name, 1000, want_fallocate=True)
            self.assertEqual(os.fstat(array2.fd).st_size, array2.bytesize)
        except OSError as e:
            # This can be raised if your filesystem does not support
            # fallocate, so we'll eat it if it happens.
            if e.errno == errno.EOPNOTSUPP:
                warnings.warn(str(e))
            else:
                raise


class TestMMapBitArray(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('o')
    
    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = i % 2
        for i, val in enumerate(self.array):
            self.assertEqual(i % 2, val)

class TestMMapInt8Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('b', -2**7, 2**7-1)

class TestMMapUint8Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('B', 0, 2**8-1)

class TestMMapInt16Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('h', -2**15, 2**15-1, size=2**18)

class TestMMapUint16Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('H', 0, 2**16-1, size=2**18)

class TestMMapInt32Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('i', -2**31, 2**31-1)

class TestMMapUint32Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('I', 0, 2**32-1)

class TestMMapInt64Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('l', -2**63, 2**63-1)

class TestMMapUint64Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('L', 0, 2**64-1)

class TestMMapFloatArray(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('f')

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = math.sqrt(i)
        for i, val in enumerate(self.array):
            assert abs(math.sqrt(i) - val) < 0.0001

class TestMMapDoubleArray(TestMMapFloatArray):
    setUp = setUp('d')
