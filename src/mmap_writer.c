/*
 * (c) 2014 Farsight Security Inc.
 * (c) 2010 Victor Ng
 *
 * Released under the MIT license.  See license.txt.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <Python.h>

#include "mmap_writer.h"

/*
 * Create the file and reallocate NULL bytes.
 *
 * Return the file descriptor to the file
 */
int open_mmap_file_rw(char* filename, size_t bytesize)
{
    int fd;
    int result;
    struct stat stat;

    /* Open a file for writing.
     * * - Creating the file if it doesn't exist.
     * *
     * * Note: "O_WRONLY" mode is not sufficient when mmaping.
     * */

    fd = open(filename, O_RDWR | O_CREAT, (mode_t)0666);
    if (fd == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error opening file for writing");
        return -1;
    }

    if (fstat(fd, &stat)) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error calling fstat");
        close(fd);
        return -1;
    }

    if (stat.st_size < bytesize) {
        /* Stretch the file size to the size of the (mmapped) array of
         * ints
         * */
        result = lseek(fd, bytesize-1, SEEK_SET);
        if (result == -1) {
            PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                               "Error calling lseek() to 'stretch' the file");
            close(fd);
            return -1;
        }
    
        /* Something needs to be written at the end of the file to
         * * have the file actually have the new size.
         * * Just writing an empty string at the current file position
         * will do.
         * *
         * * Note:
         * * - The current position in the file is at the end of the
         * stretched
         * * file due to the call to lseek().
         * * - An empty string is actually a single '\0' character, so a
         * zero-byte
         * * will be written at the last byte of the file.
         * */
        result = write(fd, "", 1);
        if (result != 1) {
            close(fd);
            PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                               "Error writing last byte of the file");
            return -1;
        }
    }

    return fd;
}

int open_mmap_file_ro(char* filepath)
{
    int fd;
    fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error opening file for reading");
        return -1;
    }
    return fd;
}

/*
 * mmap a file descriptor in read-only mode and return a char array
 */
void * map_file_ro(int fd, size_t filesize, int want_lock)
{
    void * map;
    int flags = MAP_SHARED;
    #ifdef __linux__
    if (want_lock) {
        flags |= MAP_LOCKED;
    }
    #endif
    map = mmap(0, filesize, PROT_READ, flags, fd, 0);
    if (map == MAP_FAILED) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error mmapping the file");
        close(fd);
        return 0;
    }
    return map;
}

/*
 * mmap the file descriptor in r/w/ mode.  Return the char array 
 */
void * map_file_rw(int fd, size_t filesize, int want_lock)
{
    void * map;
    int flags = MAP_SHARED;

    #ifdef __linux__
    if (want_lock) {
        flags |= MAP_LOCKED;
    }
    #endif

    map = (char *) mmap(0, filesize, PROT_READ | PROT_WRITE, flags, fd, 0);

    if (map == MAP_FAILED) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error mmapping the file");
        close(fd);
        return 0;
    }

    return map;
}

/* 
 * Don't forget to free the mmapped memory first.
 */
int unmap_file(void * map, int filesize) {
    if (munmap(map, filesize) == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error un-mmapping the file");
        return -1;
    }
    return 0;
}

int flush_to_disk(int fd)
{
    int  result;
    result = fdatasync(fd);
    if (result == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error flushing the file");
        close(fd);
        return -1;
    }
    return 0;
}

int close_file(int fd)
{
    int  result;
    flush_to_disk(fd);
    result = close(fd);
    if (result == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                           "Error closing the file");
        return -1;
    }
    return 0;
}
