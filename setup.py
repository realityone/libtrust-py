#!/usr/bin/env python
import os

from setuptools import setup

ROOT_DIR = os.path.dirname(__file__)
SOURCE_DIR = os.path.join(ROOT_DIR)

install_requires = [
    'enum34>=1.1.6',
    'cryptography>=1.9',
    'six>=1.4.1',
]

setup(
    name="libtrust-py",
    version='0.2',
    description="Integrate docker/libtrust with python.",
    url='https://github.com/realityone/libtrust-py',
    packages=['libtrust'],
    install_requires=install_requires,
    zip_safe=False,
)
