'''
MMap Arrays Test Suite

(c) 2014 Farsight Security Inc.

Released under the MIT license.  See license.txt.
'''

import math
import unittest
import tempfile
import os

import mmaparray
import six

def setUp(typecode, size=1024):
    def fn(self):
        self.backing = tempfile.NamedTemporaryFile(prefix='mmapfile_test')
        self.backing.file.close()

        self.size = size

        self.array = mmaparray.array(self.backing.name, typecode, self.size)
    return fn

def tearDown(self):
    self.array.close()
    self.backing.close()

def test_out_of_range(max_val, min_val=0):
    def fn(self):
        try:
            self.array[0] = min_val-1
        except OverflowError:
            pass
        else:
            raise AssertionError('OverflowError not raised')
        try:
            self.array[0] = max_val+1
        except OverflowError:
            pass
        else:
            raise AssertionError('OverflowError not raised')
    return fn

class TestMMapArrayGeneric:
    def test_reopen(self):
        array2 = type(self.array)(self.array.name)
        assert len(array2) == len(self.array), '{} != {}'.format(len(array2), len(self.array))

    def test_out_of_bounds(self):
        try:
            self.array[-1]
            self.array[-1] = 0
        except OverflowError:
            pass
        else:
            raise AssertionError('OverflowError not raised')

        try:
            self.array[len(self.array)]
            self.array[len(self.array)] = 0
        except IndexError:
            pass
        else:
            raise AssertionError('IndexError not raised')

    def test_setgetitem(self):
        assert self.array[0] == 0
        self.array[0] = 1
        assert self.array[0] == 1, '{} != {}'.format(self.array[0], 1)
        for i in range(1,8):
            assert self.array[i] == 0

        for i in range(1,8):
            self.array[i] = 1
        self.array[0] = 0

        assert self.array[0] == 0, '{} != {}'.format(self.array[0], 1)
        for i in range(1,8):
            assert self.array[i] == 1

    def test_len(self):
        assert len(self.array) == self.size

    def test_name(self):
        assert self.array.name == six.b(self.backing.name), "'{}' != '{}'".format(self.array.name, self.backing.name)

class TestMMapBitArray(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('o')
    tearDown = tearDown
    
    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = i % 2
        for i, val in enumerate(self.array):
            assert i % 2 == val

class TestMMapInt8Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('b')
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**7, -2**7)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+1) % 2**8 - 2**7
        for i, val in enumerate(self.array):
            assert (i+1) % 2**8 - 2**7 == val

class TestMMapUint8Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('B')
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**8)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+1) % 2**8
        for i, val in enumerate(self.array):
            assert (i+1) % 2**8 == val

class TestMMapInt16Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('h', size=2**18)
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**15, -2**15)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+1) % 2**16 - 2**15
        for i, val in enumerate(self.array):
            assert (i+1) % 2**16 - 2**15 == val

class TestMMapUint16Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('H', size=2**18)
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**16)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+1) % 2**16
        for i, val in enumerate(self.array):
            assert (i+1) % 2**16 == val

class TestMMapInt32Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('i')
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**31, -2**31)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+2**i) % 2**32 - 2**31
        for i, val in enumerate(self.array):
            assert (i+2**i) % 2**32 - 2**31 == val

class TestMMapUint32Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('I')
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**32)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+2**i) % 2**32
        for i, val in enumerate(self.array):
            assert (i+2**i) % 2**32 == val

class TestMMapInt64Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('l')
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**63, -2**63)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+2**i) % 2**64 - 2**63
        for i, val in enumerate(self.array):
            assert (i+2**i) % 2**64 -2 ** 63 == val

class TestMMapUint64Array(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('L')
    tearDown = tearDown
    test_out_of_range = test_out_of_range(2**64)

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = (i+2**i) % 2**64
        for i, val in enumerate(self.array):
            assert (i+2**i) % 2**64 == val

class TestMMapFloatArray(unittest.TestCase, TestMMapArrayGeneric):
    setUp = setUp('f')
    tearDown = tearDown

    def test_iter(self):
        for i in range(0, self.size):
            self.array[i] = math.sqrt(i)
        for i, val in enumerate(self.array):
            assert abs(math.sqrt(i) - val) < 0.0001

class TestMMapDoubleArray(TestMMapFloatArray):
    setUp = setUp('d')
