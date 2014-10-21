#cython: embedsignature=True, boundscheck=False, wraparound=False
'''
MMap Arrays: Fast, Disk-Backed Arrays for Python

(c) 2014 Farsight Security Inc.
(c) 2010 Victor Ng
'''

cimport cython
from libc.stdint cimport *

import os
import platform

import pkg_resources
import six

cdef extern from "mmap_writer.h" nogil:
    cdef void * map_file_ro(int fd, size_t filesize, int want_populate, int want_lock) except NULL
    cdef void * map_file_rw(int fd, size_t filesize, int want_populate, int want_lock) except NULL
    cdef int open_mmap_file_ro(char * filepath) except -1
    cdef int open_mmap_file_rw(char * filename, size_t bytesize) except -1
    cdef int close_file(int fd) except -1
    cdef int flush_to_disk(int fd) except -1
    cdef int unmap_file(void * map, int filesize) except -1

_typecodes = {
        'o' : MMapBitArray,
        'b' : MMapInt8Array,
        'B' : MMapUint8Array,
        'h' : MMapInt16Array,
        'H' : MMapUint16Array,
        'i' : MMapInt32Array,
        'I' : MMapUint32Array,
        'l' : MMapInt64Array,
        'L' : MMapUint64Array,
        'f' : MMapFloatArray,
        'd' : MMapDoubleArray,
        }

def array(filename, typecode, size_t size=0, read_only=False, want_populate=False, want_lock=False):
    '''
    Constructs an MMap Array of type "typecode."

    Valid Typecodes:
    'o': boolean
    'b': int8_t
    'B': uint8_t
    'h': int16_t
    'H': uint16_t
    'i': int32_t
    'I': uint32_t
    'l': int64_t
    'L': uint64_t
    'f': float
    'd': double
    '''
    if typecode in _typecodes:
        return _typecodes[typecode](filename, size, read_only, want_populate, want_lock)
    else:
        raise ValueError('Invalid typecode: \'{}\''.format(typecode))

cdef nmemb(filename, size):
    return <size_t>(os.stat(filename).st_size / size)

cdef class MMapArray:
    """
    Abstract class for MMap Arrays.
    """
    cdef void * _buffer
    cdef size_t _bytesize
    cdef size_t _size
    cdef int _fd
    cdef bytes _filename

    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if isinstance(filename, six.string_types):
            self._filename = six.b(filename)
        else:
            self._filename = filename

        self._bytesize = size

        if want_populate and (platform.system() != 'Linux' or platform.system() == 'Linux' and pkg_resources.parse_version(platform.release()) < pkg_resources.parse_version('2.5.46')):
            raise ValueError('MAP_POPULATE is only available on Linux >= 2.5.46')
        if want_lock and (platform.system() != 'Linux' or platform.system() == 'Linux' and pkg_resources.parse_version(platform.release()) < pkg_resources.parse_version('2.5.37')):
            raise ValueError('MAP_LOCKED is only available on Linux >= 2.5.37')

        if read_only:
            self._fd = open_mmap_file_ro(self._filename)

            if os.fstat(self._fd).st_size < self._bytesize:
                raise ValueError('Read-only file too short.  {} < {}'.format(os.fstat(self._fd).st_size, self._bytesize))

            self._buffer = map_file_ro(self._fd, self._bytesize, want_populate, want_lock)
        else:
            self._fd = open_mmap_file_rw(self._filename, self._bytesize)
            self._buffer = map_file_rw(self._fd, self._bytesize, want_populate, want_lock)

    def __dealloc__(self):
        self.close()

    def __getattr__(self, name):
        if name == 'name':
            return self._filename
        elif name == 'fd':
            return self._fd
        else:
            raise AttributeError("'{}' object has no attribute '{}'".format(
                self.__class__.__name__, name))

    def close(self):
        """
        Unmaps the file and closes it.
        """
        try:
            if self._fd >= 0:
                flush_to_disk(self._fd)
        finally:
            try:
                if self._buffer is not NULL:
                    unmap_file(self._buffer, self._bytesize)
                    self._buffer = NULL
            finally:
                if self._fd >= 0:
                    close_file(self._fd)
                    self._fd = -1

    def flush(self):
        """
        Flush everything to disk.
        
        Note: This calls fdatasync, not fsync.
        """
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        flush_to_disk(self._fd)

    def __setitem__(self, key, value):
        raise NotImplementedError()

    def __getitem__(self, key):
        raise NotImplementedError()

    def __iter__(self):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        return MMapIter(self)

    def __len__(self):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        return self._size

cdef class MMapBitArray(MMapArray):
    '''
    Bit (boolean) array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, 1/8.0)

        bytesize = size / 8
        if size % 8:
            bytesize += 1

        super(MMapBitArray, self).__init__(filename, bytesize, read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, value):
        cdef size_t offset = key / 8
        cdef uint8_t mask = 2 ** (key % 8)

        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        if value:
            (<uint8_t*>self._buffer)[offset] |= mask
        else:
            (<uint8_t*>self._buffer)[offset] &= ~mask

    def __getitem__(self, size_t key):
        cdef size_t offset = key / 8
        cdef uint8_t mask = 2 ** (key % 8)

        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return bool((<uint8_t*>self._buffer)[offset] & mask)

cdef class MMapInt8Array(MMapArray):
    '''
    int8_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(int8_t))

        super(MMapInt8Array, self).__init__(filename,
                size * sizeof(int8_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, int8_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<int8_t*>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<int8_t*>self._buffer)[key]

cdef class MMapUint8Array(MMapArray):
    '''
    uint8_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(uint8_t))

        super(MMapUint8Array, self).__init__(filename,
                size * sizeof(uint8_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, uint8_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<uint8_t*>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<uint8_t*>self._buffer)[key]

cdef class MMapInt16Array(MMapArray):
    '''
    int16_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(int16_t))

        super(MMapInt16Array, self).__init__(filename,
                size*sizeof(int16_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, int16_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<int16_t *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<int16_t*>self._buffer)[key]

cdef class MMapUint16Array(MMapArray):
    '''
    uint16_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(uint16_t))

        super(MMapUint16Array, self).__init__(filename,
                size*sizeof(uint16_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, uint16_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<uint16_t *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<uint16_t*>self._buffer)[key]

cdef class MMapInt32Array(MMapArray):
    '''
    int32_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(int32_t))

        super(MMapInt32Array, self).__init__(filename,
                size*sizeof(int32_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, int32_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<int32_t *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<int32_t *>self._buffer)[key]

cdef class MMapUint32Array(MMapArray):
    '''
    uint32_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(uint32_t))

        super(MMapUint32Array, self).__init__(filename,
                size*sizeof(uint32_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, uint32_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<uint32_t *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<uint32_t *>self._buffer)[key]

cdef class MMapInt64Array(MMapArray):
    '''
    int64_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(int64_t))

        super(MMapInt64Array, self).__init__(filename,
                size*sizeof(int64_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, int64_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<int64_t *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<int64_t*>self._buffer)[key]

cdef class MMapUint64Array(MMapArray):
    '''
    uint64_t array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(uint64_t))

        super(MMapUint64Array, self).__init__(filename,
                size*sizeof(uint64_t), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, uint64_t value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<uint64_t *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<uint64_t*>self._buffer)[key]

cdef class MMapFloatArray(MMapArray):
    '''
    float array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(float))

        super(MMapFloatArray, self).__init__(filename,
                size*sizeof(float), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, float value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<float *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<float*>self._buffer)[key]

cdef class MMapDoubleArray(MMapArray):
    '''
    double array.
    '''
    def __init__(self, filename, size_t size=0, read_only=False, want_populate=False, want_lock=False):
        if not size:
            size = nmemb(filename, sizeof(double))

        super(MMapDoubleArray, self).__init__(filename,
                size*sizeof(double), read_only, want_populate, want_lock)
        self._size = size

    def __setitem__(self, size_t key, double value):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        (<double *>self._buffer)[key] = value

    def __getitem__(self, size_t key):
        if self._fd < 0 or not self._buffer:
            raise ValueError('I/O operation on closed file')

        if key >= self._size:
            raise IndexError('index out of range')

        return (<double*>self._buffer)[key]

cdef class MMapIter:
    '''
    MMap Array iterator.
    '''
    cdef size_t _idx
    cdef MMapArray  _maparray

    def __cinit__(self, bitarray):
        self._maparray = bitarray
        self._idx = 0

    def __next__(self):
        if self._idx < len(self._maparray):
            result = self._maparray[self._idx]
            self._idx +=1
            return result
        raise StopIteration
