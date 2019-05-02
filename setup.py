# -*- coding: utf-8 -*-
"""
	This module contains the software's metadata and may be used to installed all of DAZER's dependencies.

"""


from setuptools import setup, find_packages


setup(
        name                    =   "dazer",
        version                 =   "1.0",
        description             =   "DAZER is a tool aiming at making the study of Docker Hub's security landscape available to anyone.",
        url                     =   "https://github.com/jonalu14/DAZER.git",
        author                  =   "Emilien Socchi, Jonathan Luu",
        author_email            =   "dockalyzer.dazer@gmail.com",
        license                 =   "MIT",
        packages                =   find_packages(),
        install_requires        =   [
                                      'requests==2.21.0',
                                      'docker==3.7.0',
                                      'speedtest-cli==2.0.2',
                                      'pyyaml==3.13',
                                      'urllib3==1.24.1'
                                    ],
        include_package_data    =   True,
        zip_safe                =   False)
