'''
(c) 2014 Farsight Security Inc.
(c) 2010 Victor Ng

Released under the MIT license.  See license.txt.
'''

from setuptools import setup
from setuptools.extension import Extension
from Cython.Distutils import build_ext
from os.path import join

import os

ext_modules=[ 
        Extension("mmaparray", 
            extra_compile_args=['-std=gnu99', '-O2', '-D_LARGEFILE64_SOURCE'],
            sources = [
                "src/mmaparray.pyx",
                'src/mmap_writer.c',],
            include_dirs = ['src'],
            ),
]

setup(
  name = 'mmaparray',
  author='Henry Stern',
  author_email = 'stern@fsi.io',
  description = 'mmap file-backed arrays for Python',
  version='0.1',
  url='https://github.com/farsightsec/mmaparray',
  download_url='https://github.com/farsightsec/mmaparray/tarball/tags/v0.1',
  license = 'MIT License',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules,
  test_suite = 'tests',
  requires = [ 'six', 'Cython (>=0.13)' ],
)
