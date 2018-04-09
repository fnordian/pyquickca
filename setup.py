#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='pyquickca',
      version='0.1',
      description='create ca and issue certs',
      author='Marcus Hunger',
      author_email='marcus.hunger@gmail.com',
      url='https://github.com/fnordian/pyquickca',
      packages=['pyquickca'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
      ],
      install_requires=['pyOpenSSL>=17', 'six', 'cryptography', 'cffi']
      )
