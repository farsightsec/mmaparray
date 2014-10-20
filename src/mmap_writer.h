/*
 * (c) 2014 Farsight Security Inc.
 * (c) 2010 Victor Ng
 *
 * Released under the MIT license.  See license.txt.
 */

#include <stdint.h>
#include <stddef.h>

int open_mmap_file_rw(char* filename, size_t bytesize);
int open_mmap_file_ro(char* filepath);
void * map_file_rw(int fd, size_t filesize, int want_populate, int want_lock);
void * map_file_ro(int fd, size_t filesize, int want_populate, int want_lock);
int flush_to_disk(int fd);
int close_file(int fd);
int unmap_file(void * map, int filesize);
