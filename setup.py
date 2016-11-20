#!/usr/bin/env python
import os

from setuptools import setup

ROOT_DIR = os.path.dirname(__file__)
SOURCE_DIR = os.path.join(ROOT_DIR)

with open(os.path.join(SOURCE_DIR, 'requirements.txt'), 'r') as f:
    requirements = f.read().splitlines()

setup(
    name="libtrust-py",
    version='0.1',
    description="Integrate docker/libtrust with python.",
    url='https://github.com/realityone/libtrust-py',
    packages=['libtrust'],
    install_requires=requirements,
    zip_safe=False,
)
