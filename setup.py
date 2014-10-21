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
  description = 'MMap File-Backed Arrays for Python',
  long_description = open('README.rst').read(),
  version='0.4',
  url='https://github.com/farsightsec/mmaparray',
  license = 'MIT License',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules,
  test_suite = 'tests',
  requires = [ 'six', 'Cython (>=0.13)' ],
  classifiers = [
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Cython',
    'Intended Audience :: Developers',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Topic :: Software Development :: Libraries',
  ],
)
