#!/usr/bin/env python3
# setup.py -*-python-*-

import setuptools
#import urm

setuptools.setup(
    name = "urm",
    version = "0.0.1",
    #version = urm.__version__,
    license = "MIT",
    author = "Rickard E. (Rik) Faith",
    scripts = ['bin/urm'],
    packages= setuptools.find_packages(),
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)

