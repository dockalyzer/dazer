#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
	This module contains functions interacting with version 1 of Microbadger's API.

"""


import logging
import requests


microbadger_api_v1 = "https://api.microbadger.com/v1/"
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}


def get_repository_query_v1(repository):
	"""
		Retrieves the passed repository using Microbadger's API version 1.


		Args:
			repository	(string):	the repository to be retrieved


		Return:
			dict:	the query's result in Json format when successful (note: may be empty), None otherwise

	"""
	query_result = None
	image_api    = microbadger_api_v1 + "images/"
	request      = image_api + repository
	response     = requests.get(request, headers=headers)

	if response.ok:
		query_result = response.json()

	else:
		logging.error("Request to Microbadger's API version 1 failed (change in the API?)")

	return query_result


def get_repository_tag_query_v1(repository, repository_tag):
	"""
		Retrieves the passed tag object for the passed repository using Microbadger's API.


		Args:
			repository			(string):	the repository to retrieve the passed tag for
			repository_tag		(string):	the tag to retrieve


		Returns:
			dict: a dictionary representing the retrieved tag object

	"""
	tag_object = ""
	result     = get_repository_query_v1(repository)

	if result and result is not None:
		is_retrieved = False
		versions     = result.get("Versions")

		if versions and versions is not None:
			for version in versions:
				if is_retrieved:
					break

				tags = version.get("Tags")

				for tag in tags:
					if tag.get("tag") == repository_tag:
						tag_object   = version
						is_retrieved = True
						break

	return tag_object





