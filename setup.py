# -*- encoding: utf8 -*-
#
# Copyright (c) 2021-2022 ESET spol. s r.o.
# Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
# See LICENSE file for redistribution.

from setuptools import setup

setup(
    name='WslinkVMAnalyzer',
    version='1.0.0',
    py_modules=['WslinkVMAnalyzer'],
    url='https://github.com/eset/wslink-vm-analyzer',
    license='BSD',
    author='Vladislav Hrčka',
    author_email='vladislav.hrcka@eset.com',
    description='Tool to facilitate analysis of code obfuscated with Wslink\'s virtual machine',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
    ],
    install_requires=[
        'miasm @ git+https://github.com/cea-sec/miasm@9a36c6d7849335c83a9460fc558afb55ff0a2aa1',
    ],
    keywords=[
        "reverse engineering",
        "Wslink",
        "virtual machine",
        "deobfuscation",
    ]
)
