#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    This module contains initialization functions, ensuring that all of the script's requirements are met.

"""


import sys
import pkg_resources as pkg


def verify_python_version():
    """
        Verifies whether this script is running with Python version 3.


        Returns:
            bool: True if Python 3 is used, False otherwise.
    """
    if sys.version_info[0] < 3:
        return False

    return True


def verify_installed_packages(packages_required):
    """
        Verifies whether the passed Python packages are installed on the system running this script.


        Args:
            packages_required (list): The list of Python packages to be verified


        Returns:
            list: 	a list of non installed packages

    """
    non_installed_packages  = []
    installed_packages      = pkg.working_set
    installed_packages_list = sorted(["%s==%s" % (p.key, p.version) for p in installed_packages])

    for package in packages_required:
        if package not in installed_packages_list:
            non_installed_packages.append(package)

    return non_installed_packages
