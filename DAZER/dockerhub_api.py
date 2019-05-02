#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
	This module contains functions interacting with bother version 1 and 2 of Docker Hub's API.

"""


import json
import logging
import os
import random
import re
import requests
from DAZER import utils
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


dockerhub_api_v1 = "https://hub.docker.com/api/content/v1/"
dockerhub_api_v2 = "https://hub.docker.com/v2/"
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
#-- Retrying the request three times before an exception raises
session = requests.Session()
retries = Retry(connect=3, backoff_factor=30)
adapter = HTTPAdapter(max_retries=retries)
session.mount('http://', adapter)
session.mount('https://', adapter)


def search_query_v1(query):
	"""
		Interrogates the version 1 of Docker Hub's search API with the passed query.


		Args:
			query	(string):	the query to be searched for


		Returns:
			dict:	the query's result in Json format when successful (note: may be empty), None otherwise

	"""
	query_result = None
	search_api   = dockerhub_api_v1 + "products/search?q="
	request      = search_api + query  						#-- e.g. certification_status=certified&page_size=1"
	response     = requests.get(request, headers=headers)

	if response.ok:
		query_result = response.json()

		if not query_result.get("summaries"):
			logging.warning("Empty result from Docker Hub's search API version 1")
	else:
		logging.error("Request to Docker Hub's search API version 1 failed (change in the API?)")

	return query_result


def get_repository_query_v1(repository, is_insecure = False):
	"""
		Retrieves the passed repository using Docker Hub's image API version 1.


		Note 1:
			The images retrieved using version 1 of Docker Hub's image API contains a lot more details than the ones retrieved using version 2.

		Note 2:
			The version 1 of Docker Hub's image API is NOT able to retrieve 'community' images (only 'official', 'certified' and 'verified').

		Note 3:
			For special purposes, this function may be called in a manner that is insecure by omitting the logging of unexpected events.


		Args:
			repository	(string):	the repository to be retrieved (note: the API id of the repository to be retrieved is also accepted - e.g. 3567eb02-06cf-48e2-978f-cbd86cc3e61d)
			is_insecure   (bool):   whether the function should log unexpected events


		Return:
			dict:	the query's result in Json format when successful (note: may be empty), None otherwise

	"""
	query_result = None
	image_api    = dockerhub_api_v1 + "products/images/"
	request      = image_api + repository
	response     = requests.get(request, headers=headers)

	try:
		session.get(request)

		if response.ok:
			query_result = response.json()

			if "message" in query_result:
				logging.warning(repository + " got empty result from Docker Hub's image API version 1")

		elif not is_insecure:
			logging.error("Request to Docker Hub's image API version 1 failed (change in the API?)")

	except requests.exceptions.ConnectionError:
		logging.exception("Error for request: " + request)

	return query_result


def search_query_v2(query):
	"""
		Interrogates the version 2 of Docker Hub's search API with the passed query.


		Args:
			query	(string):	the query to be searched for


		Returns:
			dict:	the query's result in Json format when successful (note: may be empty), None otherwise

	"""
	query_result = None
	search_api = dockerhub_api_v2 + "search/repositories/?query="
	request = search_api + query  									#-- e.g. library&is_official=true&page=1"
	response = requests.get(request, headers=headers)


	try:
		session.get(request)
		if response.ok:
			query_result = response.json()

			if not query_result.get("results"):
				logging.warning("Empty result from Docker Hub's search API version 2")
		else:
			logging.error("Request to Docker Hub's search API version 2 failed (change in the API?)")

	except requests.exceptions.ConnectionError:
		logging.exception("Error for request: " + request)

	return query_result


def get_repository_query_v2(repository, is_insecure = False):
	"""
		Retrieves the passed repository using Docker Hub's image API version 2.


		Note 1:
			The images retrieved using version 2 of Docker Hub's image API contain less details than the ones retrieved using version 1.

		Note 2:
			The version 2 of Docker Hub's image API is NOT able to retrieve 'certified' and 'verified' images (only 'official' and 'community').


		Args:
			repository	(string):	the repository to be retrieved (note: the API id of the repository to be retrieved is also accepted - e.g. 3567eb02-06cf-48e2-978f-cbd86cc3e61d)
			is_insecure   (bool):   whether the function should log unexpected events


		Return:
			dict:	the query's result in Json format when successful (note: may be empty), None otherwise

	"""
	query_result = None
	image_api    = dockerhub_api_v2 + "repositories/"
	request      = image_api + repository
	response     = requests.get(request, headers=headers)


	try:
		session.get(request)

		if response.ok:
			query_result = response.json()

			if "detail" in query_result:
				logging.warning(repository + " got empty result from Docker Hub's image API version 2")

		elif not is_insecure:
			logging.error("Request to Docker Hub's image API version 2 failed (change in the API?)")

	except requests.exceptions.ConnectionError:
		logging.exception("Error for request: " + request)

	return query_result


def get_repository_tags_query_v2(repository):
	"""
		Retrieves all the available tags for the passed repository using Docker Hub's tags API.


		Args:
			repository	(string):	the repository to be retrieved for tags


		Returns:
			list: a list of retrieved tags for the passed repository

	"""
	tags     = []
	tags_api = dockerhub_api_v2 + "repositories/"
	request  = tags_api + repository + "/tags/?page_size=1"
	response = requests.get(request, headers=headers)


	try:
		session.get(request)

		if response.ok and not response.json().get("detail"):
			total_images  = response.json().get("count")  																					#-- the total number of images to be fetched
			fetching_size = 50  																											#-- the number of json objects to fetch per request
			total_pages   = total_images // fetching_size + 1 if total_images % fetching_size > 0 else total_images // fetching_size		#-- the total number of pages to request for complete retrieval

			for page in range(1, total_pages + 1):
				#-- Retrieving one page
				request  = tags_api + repository + "/tags/?page_size=" + str(fetching_size) + "&page=" + str(page)
				response = requests.get(request, headers=headers)

				if response.ok and response.json().get("results"):
					images = response.json().get("results")

					for image in images:
						tags.append(image.get("name"))
				else:
					logging.warning(repository + " got empty result from Docker Hub's tags API")
					logging.warning("Sent request: " + request)
		else:
			logging.error("Request to Docker Hub's tags API failed (change in the API?)")

	except requests.exceptions.ConnectionError:
		logging.exception("Error for request: " + request)

	return tags


def get_repository_tag_query_v2(repository, tag):
	"""
		Retrieves the passed tag object for the passed repository using Docker Hub's tags API.


		Args:
			repository	(string):	the repository to retrieve the passed tag for
			tag			(string):	the tag to retrieve


		Returns:
			dict: a dictionary representing the retrieved tag object

	"""
	tag_json = ""
	tags_api = dockerhub_api_v2 + "repositories/"
	request = tags_api + repository + "/tags/" + tag
	response = requests.get(request, headers=headers)


	try:
		session.get(request)
		if response.ok and not response.json().get("detail"):
			tag_json = response.json()
		else:
			logging.error("Request to Docker Hub's tags API failed (change in the API?)")

	except requests.exceptions.ConnectionError:
		logging.exception("Error for request: " + request)

	return tag_json


def has_repository_tag_query_v2(repository, tag):
	"""
		Verifies whether the passed repository has a the passed tag using Docker Hub's tags API.


		Args:
			repository	(string):	the repository to be retrieved for the passed tag
			tag			(string):	the tag to be verified for existence


		Returns:
			bool: True if the passed repository has the passed tag, False otherwise

	"""
	has_latest_tag = False

	tags_api = dockerhub_api_v2 + "repositories/" + repository + "/tags/"
	request  = tags_api + tag
	response = requests.get(request, headers=headers)

	try:
		session.get(request)

		if response.ok:
			has_latest_tag = True

	except requests.exceptions.ConnectionError:
		logging.exception("Error for request: " + request)

	return has_latest_tag


def get_repository_type(repository):
	"""
		Retrieves the type of the passed repository as being of of the following types: official, certified, verified, community.


		Args:
			repository	(string):	the repository to be retrieved


		Returns:
			string:		the type of the passed repository if successful, an empty string otherwise

	"""
	image_type = ""
	image      = get_repository_query_v1(repository, is_insecure = True)

	if image:
		default_plan = image.get("plans")[0]
		namespace = default_plan.get("repositories")[0].get("namespace")

		if namespace == "library":
			image_type = "official"

		elif namespace == "store":
			certification_status = default_plan.get("certification_status")
			image_type           = "certified" if certification_status == "certified" else "verified"

	else:
		repository = get_repository_query_v2(repository, is_insecure = True)

		if repository is not None and "namespace" in repository:
			image_type = "community"

	return image_type


def get_latest_versioned_tag(repository):
	"""
		Retrieves the most recent versioned tag (last pushed) of the passed repository.


		Note:
			A versioned tag may have different formats such as:
				- 1
				- 1.2
				- 1.2.3
				- v1.2.3
				- 1.2.3-alpine
				- v1.2.3-alpine


		Args:
			repository	(string):	the repository to be retrieved for its most recent versioned tag


		Returns:
			string:		the most recent  versioned tag of the passed repository

	"""
	tag  = ""
	tags = get_repository_tags_query_v2(repository)

	if len(tags) != 0:
		tag = tags[0]

	return tag


def get_official_images():
	"""
		Retrieves the name, latest tag and slug name of all the official images available on Docker Hub.


		Note 1:
			The retrieval is executed iteratively by fetching 50 Json objects (i.e. images) per request.


		Note 2:
			Official repositories are located in the '/library' namespace.


		Returns:
			list:	a list of dictionaries with the retrieved information

	"""
	images = []
	excluded_repositories = ["scratch", "rocket.chat"]  	#-- repositories which are indexed by the Docker Hub API but do not contain real images

	query = "library&is_official=true&page_size=1"
	result = search_query_v2(query)

	if result is not None and result.get("results"):
		total_images = result.get("count") 	 																							#-- the total number of images to be fetched
		fetching_size = 50  																											#-- the number of json objects to fetch per request
		total_pages   = total_images // fetching_size + 1 if total_images % fetching_size > 0 else total_images // fetching_size		#-- the total number of pages to request for complete retrieval

		for page in range(1, total_pages + 1):
			#-- Retrieving one page
			query = "library&is_official=true&page_size=" + str(fetching_size) + "&page=" + str(page)
			result = search_query_v2(query)

			if result and result.get("results"):
				for image in result.get("results"):
					repository = str(image.get("repo_name"))
					tag = ""

					if repository not in excluded_repositories:
						#-- Retrieving the necessary information for each of the repository on the current page
						tag = get_latest_versioned_tag("library/" + repository)

						if tag:
							images.append({
								"name": repository,
								"tag": 	tag,
							})
						else:
							logging.info("%s - Image retrieval skipped (missing tag)", repository)
	return images


def get_certified_images():
	"""
		Retrieves the name, latest tag and slug name of all the certified images available on Docker Hub.


		Note 1:
			The retrieval is executed iteratively by fetching 50 Json objects (i.e. images) per request.


		Note 2:
			Certified repositories are located in the '/store/<username>' namespace and use unpredictable tags (e.g. '/store/ibmcorp/websphere-liberty:microProfile2')


		Returns:
			list:	a list of dictionaries with the retrieved information

	"""
	images = []  															#-- the list of dictionaries containing all the certified images' names, tags and slug names
	query  = "&type=image&certification_status=certified&page_size=1"
	result = search_query_v1(query)
	
	if not result.get("message") and result.get("summaries"):
		total_images  = result.get("count")  																							#-- the total number of images to be fetched
		fetching_size = 50  																											#-- the number of json objects to fetch per request
		total_pages   = total_images // fetching_size + 1 if total_images % fetching_size > 0 else total_images // fetching_size		#-- the total number of pages to request for complete retrieval
		
		for page in range(1, total_pages + 1):
			#-- Retrieving one page
			query  = "&type=image&certification_status=certified&page_size=" + str(fetching_size) + "&page=" + str(page)
			result = search_query_v1(query)
			
			if result is not None and result.get("summaries"):
				for image in result.get("summaries"):
					#-- Retrieving name and tag
					image_name = image.get("slug")
					name       = ""
					tag        = ""
					result     = get_repository_query_v1(image_name)
					
					if not result.get("message"):
						#-- Determining the retrieving method
						if re.search("microsoft", image_name):
							#-- Microsoft specific retrieval
							description = result.get("full_description")
							name        = re.search("docker pull ([.\/\w-]+)", description)  																			#-- e.g. 'docker pull mcr.microsoft.com/oryx/nodejs' or 'docker pull microsoft-mssql-tools'

							if not name:
								logging.info("Repository skipped ('" + image_name + "' does not contain images or explicit pulling instructions)")
								continue

							name = name.group(1)
							tag  = re.search("docker pull.*?:([.\w\d:-]+)", description).group(1) if  re.search("docker pull.*?:([.\w\d:-]+)", description) else "latest" 	#-- e.g. '3.2.1', 'v3'
						else:
							#-- Normal retrieval
							default_plan = result.get("plans")[0]
							repository   = default_plan.get("repositories")[0]
							version      = default_plan.get("versions")[0]
							name         = repository.get("namespace") + "/" + repository.get("reponame")
							tag          = version.get("tags")[0].get("value") if version.get("tags")[0].get("value") else "latest"
					
						images.append({
							"name": 		name,
							"tag": 			tag,
							"slug_name": 	image_name
						})
	return images


def get_verified_images():
	"""
		Retrieves the name, latest tag and slug name of all the verified images available on Docker Hub.


		Note 1:
			The retrieval is executed iteratively by fetching 50 Json objects (i.e. images) per request.


		Note 2:
			Verified repositories which are non-Microsoft are located in the '/store/<username>' namespace and use unpredictable tags (e.g. 'store∕saplabs/hanaexpressxsa:2.00.033.00.20180925.2').
			Microsoft repositories use a complete different namespace scheme proper to them and tend to use the 'latest' tag for all of their images.


		Note 3:
			Certain Microsoft repositories are listed out with different names on Docker Hub, but are actually the same as they use the same docker pull command (e.g. the 'Oryx node-x.y' repositories)


		Returns:
			list:	a list of dictionaries with the retrieved information

	"""
	images = []
	query = "&type=image&image_filter=store&page_size=1"
	result = search_query_v1(query)
	
	if result is not None and result.get("summaries"):
		total_images  = result.get("count")  																							#-- the total number of images to be fetched
		fetching_size = 50  																											#-- the number of json objects to fetch per request
		total_pages   = total_images // fetching_size + 1 if total_images % fetching_size > 0 else total_images // fetching_size		#-- the total number of pages to request for complete retrieval
		
		for page in range(1, total_pages + 1):
			#-- Retrieving one page
			query = "&type=image&image_filter=store&page_size=" + str(fetching_size) + "&page=" + str(page)  #-- returns both Official and Verified images
			result = search_query_v1(query)
			
			if result is not None and result.get("summaries"):
				for image in result.get("summaries"):
					#-- Verifying that the image is of type Verified
					image_name = image.get("slug")
					image_type = get_repository_type(image_name)
					
					if image_type is "verified": # or image_type is "certified":
						#-- Retrieving name and tag
						result = get_repository_query_v1(image_name)
						name   = ""
						tag    = ""
						
						if not result.get("message"):
							#-- Determining the retrieving method
							if re.search("microsoft", image_name):
								#-- Microsoft specific retrieval
								description = result.get("full_description")
								name = re.search("docker pull ([.\/\w-]+)", description)  #-- e.g. 'docker pull mcr.microsoft.com/oryx/nodejs' or 'docker pull microsoft-mssql-tools'

								if not name:
									logging.info("Repository skipped ('" + image_name + "' does not contain images or explicit pulling instructions)")
									continue
								
								name = name.group(1)
								tag  = re.search("docker pull.*?:([.\w\d:-]+)", description).group(1) if re.search("docker pull.*?:([.\w\d:-]+)", description) else "latest"   	#-- e.g. '3.2.1', 'v3'

								#-- Filtering out a potential duplicate repository
								is_retrieved = False

								for image in images:
									if name == image.get("name"):
										is_retrieved = True
										break

								if is_retrieved:
									continue
							
							else:
								#-- Normal retrieval
								default_plan = result.get("plans")[0]
								repository   = default_plan.get("repositories")[0]
								version      = default_plan.get("versions")[0]
								name         = repository.get("namespace") + "/" + repository.get("reponame")
								tag          = version.get("tags")[0].get("value") if version.get("tags")[0].get("value") else "latest"
						
							images.append({
								"name": 		name,
								"tag": 			tag,
								"slug_name": 	image_name
							})
	return images


def get_community_images(x_images):
	"""
			Retrieves the name and latest tag of the passed number of community images among the most popular ones available on Docker Hub.


			Note 1:
				The retrieval is executed iteratively by fetching 50 Json objects (i.e. images) per request.


			Note 2:
				Community repositories are located in the '<username>' namespace (e.g. '/pivotalcf/pivnet-resource:latest')


			Note 3:
				The returned images are chosen randomly between the passed number of images times 3 for increasing randomness across multiple calls to this function.


			Args:
			x_images	(int):	the base number of images to be retrieved


			Returns:
				tuple:	two lists of dictionaries with the retrieved information (one with the first passed number of retrieved images, another one with the rest of the retrieval)

	"""
	images = []
	query = "%2B&is_official=false&ordering=-pull_count&page_size=1"
	result = search_query_v2(query)
	excluded = ["bugswarm/artifacts", "microsoft/oms", "programmerq/scaletest", "newrelic/nrsysmond", "weaveworks/weave-npc"]
	
	if result is not None and result.get("results"):
		total_images  = x_images * 3  																									#-- the total number of images to analyze, original value times three
		fetching_size = 50  																											#-- the number of json objects to fetch per request
		total_pages   = total_images // fetching_size + 1 if total_images % fetching_size > 0 else total_images // fetching_size		#-- the total number of pages to request for complete retrieval
		
		counter = 0  								#-- counting for every single image that are being analyzed
		for page in range(1, total_pages + 1):
			#-- Retrieving one page
			query = "%2B&is_official=false&ordering=-pull_count&page_size=" + str(fetching_size) + "&page=" + str(page)
			result = search_query_v2(query)
			
			if result is not None and result.get("results"):
				for image in result.get("results"):
					if counter < total_images:
						repository = str(image.get("repo_name"))
						tag        = get_latest_versioned_tag(repository)
						if repository not in excluded:
							if tag:
								images.append({
									"name": repository,
									"tag": 	tag
								})
						
							else:
								logging.info("%s - Image retrieval skipped (missing tag)", repository)
								counter -= 1
						else:
							logging.info("%s - repository skipped due to DNS resolve problems", repository)
							counter -= 1
					else:
						break
			
					counter += 1

	random.shuffle(images)
	requested = images[:x_images]
	remaining = images[x_images:]

	return requested, remaining


def get_image_extrainfo(image_name):
	"""
		Retrieves and parses extra information (type and total pulled) for the image with the passed name using Docker Hub's repository API.


		Note 1:
			Images of type 'community' cannot be retrieved using the version 1 of Docker Hub's API and are therefore retrieved via version 2.
			Other image types ('certified', 'verified', 'official') are retrieved using version 1.


		Note 2:
			The passed image name must be a slug name or a Hub ID for certified and verified images, as version of the Docker Hub only understands slug names and image ids.


		Args:
			image_name	(string):	the name of the image to be retrieved and parsed for extra information


		Return:
			dict: 	a dictionary containing the parsed information from retrieved image

	"""
	repository_type = get_repository_type(image_name)
	total_pulled    = 0

	if repository_type != "community":
		#-- Using version 1 of Docker Hub's repository API
		result = get_repository_query_v1(image_name)
		
		if result:
			total_pulled = result.get("popularity")

	else:
		#-- Using version 2 of Docker Hub's repository API
		result = get_repository_query_v2(image_name)

		if result:
			total_pulled = result.get("pull_count")

	return 	{
				"type": 		repository_type,
				"total_pulled": total_pulled
			}


def get_image_parent(repository, image_layers, db_type):
	"""
		Retrieves the tagged parent of the image with the passed layers, belonging to the passed repository from the passed type of parent database.


		Args:
			repository		(string):	the name of the repository that the image to retrieve the parent for belongs to
			image_layers	(string):	the complete layer combination of the image to retrieve the parent for
			db_type			(string):	the type of parent database to retrieve from ('official' and 'verified')


		Returns:
			dict:		the parent repository name and tag of the image with the passed layers or an empty dict if no parent is found


		Raises:
			IOError:	on database file reading failure

	"""
	parent          = dict()
	image_id_length = 12																								#-- the length of a single fs layer id (e.g. 6ae821421a7d)
	image_ids       = [image_layers[id:id + image_id_length] for id in range(0, len(image_layers), image_id_length)]	#-- splitting image_layers into a list of single layer ids with a length of image_id_length
	home            = os.path.dirname(os.path.realpath(__file__))
	base_dir        = os.path.join(home, "json/parent_db")

	if db_type == "official":
		parent_files = [os.path.join(base_dir, resource) for resource in os.listdir(base_dir) if re.search("(official)", resource)]

	elif db_type == "verified":
		parent_files = [os.path.join(base_dir, resource) for resource in os.listdir(base_dir) if re.search("(verified)", resource)]

	else:
		return ""

	parent_file = utils.get_most_recent_file(parent_files)		#-- the file containing all the unique layers for all the images in the repositories of the passed type

	try:
		with open(parent_file, "r") as file:
			base_db = json.loads(file.readline())

		repositories = list(base_db.keys())
		index        = repositories.index(repository)
		repositories = repositories[:repositories.index(repository)] + repositories[repositories.index(repository) + 1:]	#-- all the repositories apart from the passed one
	
	except IOError:
		raise

	except:
		pass

	current_layers = ""

	#-- Retrieving parent
	for image_id in image_ids:
		current_layers = current_layers + image_id

		for repo in repositories:
			for image in base_db[repo]:
				if current_layers == image.get("fs_layers"):

					#-- The repository is a parent
					parent = {
								"name": 	repo,
								"tag":		image.get("image_tag")
							 }

			#-- Continuing, as the image's closest parent is among the lower layers

	return parent
