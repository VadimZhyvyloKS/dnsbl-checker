#!/usr/bin/env python

from os import path as op

from setuptools import setup


def _read(fname):
    try:
        return open(op.join(op.dirname(__file__), fname)).read()
    except IOError:
        return ''


install_requires = [
    l for l in _read('requirements.txt').split('\n')
    if l and not l.startswith('#')
]

setup(
    name='dnsbl_checker',
    version='0.1',
    description='Asynchronous script for monitoring dns blacklists',
    author='Vadim Zhyvylo',
    author_email='jyvylo5@gmail.com',
    url='https://github.com/VadimZhyvyloKS/dnsbl-checker',
    license='MIT',
    install_requires=install_requires,
    keywords='dns blacklist dnsbl async check',
    incude_package_data=True,
    packages=['src'],
    entry_points='''
        [console_scripts]
        dnsbl=cli:cli
    '''
)
