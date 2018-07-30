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
    version='0.0.2',
    description='Asynchronous script for monitoring dns blacklists',
    long_description=_read('README.md'),
    author='Vadim Zhyvylo',
    author_email='jyvylo5@gmail.com',
    url='https://github.com/VadimZhyvyloKS/dnsbl-checker',
    license='MIT',
    install_requires=install_requires,
    keywords='dns blacklist dnsbl async asynchronous check',
    include_package_data=True,
    packages=['dnsbl_checker'],
    entry_points='''
        [console_scripts]
        dnsbl=dnsbl_checker.cli:cli
    '''
)
