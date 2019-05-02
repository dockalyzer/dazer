#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
	This module	gathers the very last layer of all the images present in each repository of the passed type and exports them to a Json file referred to as a "parent database" of the following format:

		{
			"mongo": [
								{
									"fs_layers":		"f3d19635b0dc",
									"image_tag":    	"v1.2",
									"last_updated":		"34534345753567",
									"created":			"34534345753567"
								},
								{
									"fs_layers":		"re349635b0ed",
									"image_tag":    	"3.1.0",
									"last_updated":		"34534345753567",
									"created":			"1294348944848"
								}
								...
					 ],

			"ubuntu": [
								{
									"fs_layers":		"dc8a54b8000b",
									"image_tag":    	"1",
									"last_updated":		"0348593458558",
									"created":			"34534345753567"
								},
								{
									"fs_layers":		"ab8fbc38cdf2",
									"image_tag":    	"latest",
									"last_updated":		"34534345753567",
									"created":			"1294348944848"
								}
								...
					  ],

			...
		}


	Note 1:
		This module may be used as a standalone script to populate the parent database of the passed type from scratch or update it in case it already exists.


	Note 2:
		For optimization reasons, the layer retrieval is executed by abusing of the Docker Engine's pull command, avoiding to download images as much as possible.


	Note 3:
		This module is a prerequisite to the Docker vulnerability AnalyZER (DAZER), as it allows the latter to retrieve an image's parent.

"""


import argparse
import calendar
import datetime
import docker
import json
import logging
import os
import re
import shutil
import time
import yaml

from DAZER import dockerhub_api
from DAZER import image_analyzer
from DAZER import initialization
from DAZER import microbadger_api
from DAZER import utils


#-- Credentials
dockerhub_username = ""
dockerhub_password = ""

#-- Initializing credentials
try:
	home = os.path.dirname(os.path.realpath(__file__))
	credentials_file = os.path.join(home, "DAZER/credentials.yml")

	with open(credentials_file, "r") as ymlfile:
		config_file = yaml.load(ymlfile)

	dockerhub_username = config_file["dockerhub_api"].get("username")
	dockerhub_password = config_file["dockerhub_api"].get("password")

except:
	logging.exception("Failed to open " + credentials_file)


def init():
	"""
		Verifies whether the machine running this script meets all of its requirements.


		Returns:
			None

	"""
	#-- Ensuring using Python 3
	if not initialization.verify_python_version():
		print("You are not using Python 3!")
		print("Exiting ...")
		os._exit(0)

	#-- Ensuring all necessary packages are installed
	packages_required = [
							"requests==2.21.0",
							"docker==3.7.0",
							"speedtest-cli==2.0.2",
							"pyyaml==3.13"
						]
	non_installed_packages = initialization.verify_installed_packages(packages_required)

	if non_installed_packages:
		for package in non_installed_packages:
			print(package + " is either missing or does not satisfy the required version of this package")

		print("")
		print("You  may install all the required packages by DAZER using: 'pip3 install .'")
		print("Exiting ...")
		os._exit(0)


def validate_input():
	"""
		Ensures that the arguments passed to this script are valid to its requirements.


		Returns:
			None

	"""
	parser = argparse.ArgumentParser(
		description     = "Gathers the layers of all the unique images located in all of Docker Hub's repositories of the passed type in JSON format.\n"
						  "Note that this software is a prerequisite to the Docker vulnerability AnalyZER (DAZER), as it allows the latter to find an image's parent(s).\n",
		formatter_class = argparse.RawTextHelpFormatter
	)

	parser.add_argument(
		"type",
		default=["official", "verified"],
		nargs="?",
		help="Choose between 'official', or 'verified'"
	)

	return parser.parse_args()


def get_layers_image(name, tag):
	"""
		Retrieves all the FS layers of the image with the passed name and tag.


		Note:
			Images are never actually downloaded, as their pulling through the Docker Engine is stopped once all their layers have been retrieved.


		Args:
			name	(string):	the name of the image to be retrieved
			tag		(string):	the tag  of the image to be retrieved


		Returns:
			string: 	the FS layer combination of the image with the passed name and tag

	"""
	fs_layer_ids       = ""  			#-- the tagged image's combination of all layers
	is_retrieved       = False			#-- whether the tagged image's layer ids have been retrieved
	retrials           = 3 + 2 			#-- number of times to retry retrieving on failure
	retrials_wait_time = 30  			#-- number of seconds to wait between failed retrieval retrials

	for retrial in range(1, retrials):
		if is_retrieved:
			break

		try:
			client = docker.APIClient(base_url = "unix://var/run/docker.sock", timeout = 1800)
			client.login(dockerhub_username, dockerhub_password, reauth = True)

			for line in client.pull(repository = name, tag = tag, stream = True, decode = True):
				#-- Streaming the image's pulling action in real time
				if line.get("status") == "Pulling fs layer" or line.get("status") == "Already exists":
					#-- Retrieving one layer
					fs_layer_ids += line.get("id")

				elif line.get("error"):
					#-- Retrieval failed for misc reason without throwing an explicit error (e.g. incompatible platform, gateway timeout, etc.)
					if re.search("cannot be used on this platform", str(line.get("error"))) or re.search("no matching manifest", str(line.get("error"))) and re.search("microsoft", name) or re.search("no matching manifest", str(line.get("error"))):
						#-- Incompatible platform
						raise docker.errors.APIError("cannot be used on this platform")
					else:
						#-- Misc reason without throwing an explicit error (e.g. gateway timeout, etc.)
						raise docker.errors.APIError("")

				elif line.get("status") == "Downloading":
					#-- All the layers have been retrieved
					is_retrieved = True
					break

		except docker.errors.APIError as e:
			if re.search("cannot be used on this platform", str(e)):
				#-- Incompatible platform
				logging.info("Incompatible platform for image: %s", name + ":" + tag)
				break

			elif re.search("docker login", str(e)):
				#-- The image has not been checked out or the login may have failed
				logging.warning("Docker login required for image: %s", name + ":" + tag)

			else:
				#-- Retrieval failed for misc reason (e.g. internal server error, busy server, etc.)
				logging.warning("Image retrieval failed")
				fs_layer_ids = ""

			if retrial < retrials - 1:
				time.sleep(retrials_wait_time)
				logging.info("Retrying to retrieve %s [%s/%s] ...", name + ":" + tag, str(retrial), str(retrials - 2))
				continue

	return fs_layer_ids


def get_layers_official_repository(repository):
	"""
		Retrieves all the layers, tags, creation dates and last updated times of all the images in the passed Official repository.


		Note:
			Images are never actually downloaded, as their pulling through the Docker Engine is stopped once all their layers have been retrieved.


		Args:
			repository	(string):	the name of the Official repository to be retrieved


		Returns:
			list: 	a list of dictionaries containing successfully retrieved images from the passed repository

	"""
	logging.info("Retrieving all tags in repository: " + repository)

	images           = []
	repository_tags  = dockerhub_api.get_repository_tags_query_v2("library/" + repository)

	logging.info("Tags retrieved: " + str(len(repository_tags)))

	for repository_tag in repository_tags:
		#-- Retrieving the tagged image's FS layer ids
		image_name         = repository			#-- the image to be retrieved
		image_tag          = repository_tag		#-- the tag   to be retrieved
		fs_layer_ids       = ""					#-- the tagged image's combination of all layers
		is_retrieved       = False				#-- whether the tagged image's layer ids have been retrieved
		retrials           = 3 + 2 				#-- number of times to retry retrieving on failure
		retrials_wait_time = 30  				#-- number of seconds to wait between failed retrieval retrials

		logging.info("Retrieving %s", image_name + ":" + image_tag)

		for retrial in range(1, retrials):
			if is_retrieved:
				break

			try:
				client = docker.APIClient(base_url = "unix://var/run/docker.sock", timeout = 1800)
				client.login(dockerhub_username, dockerhub_password, reauth = True)

				for line in client.pull(repository = repository, tag = repository_tag, stream = True, decode = True):
					#-- Streaming the image's pulling action in real time
					if line.get("status") == "Pulling fs layer" or line.get("status") == "Already exists":
						#-- Retrieving one layer
						fs_layer_ids += line.get("id")

					elif line.get("status") == "Downloading":
						#-- All the layers have been retrieved
						logging.info("Retrieved: %s", fs_layer_ids)
						is_retrieved = True
						break

			except docker.errors.APIError:
				#-- Retrieving failed for misc reason (e.g. internal server error, busy server, etc.)
				logging.warning("Image retrieval failed")
				fs_layer_ids = ""

				if retrial < retrials - 1:
					time.sleep(retrials_wait_time)
					logging.info("Retrying to retrieve %s [%s/%s] ...", image_name + ":" + image_tag, str(retrial), str(retrials - 2))
					continue

		if fs_layer_ids:
			#-- Filtering out potential duplicates due to identical images having different tags
			is_retrieved = False

			for image in images:
				if fs_layer_ids == image.get("fs_layers"):
					is_retrieved = True
					break

			if not is_retrieved:
				result = dockerhub_api.get_repository_tag_query_v2("library/" + repository, repository_tag)

				if result:
					last_updated = ""

					if result.get("last_updated"):
						utc_time     = time.strptime(result.get("last_updated"), "%Y-%m-%dT%H:%M:%S.%fZ")
						last_updated = calendar.timegm(utc_time)  									#-- utc epoch timestamp
					else:
						#-- The image is too old and does not have any 'last updated' timestamp
						last_updated = 0

					result = microbadger_api.get_repository_tag_query_v1("library/" + repository, repository_tag)

					if result:
						utc_time = time.strptime(result.get("Created"), "%Y-%m-%dT%H:%M:%S.%fZ")
						created  = calendar.timegm(utc_time)										#-- utc epoch timestamp

						images.append({
											"fs_layers":	fs_layer_ids,
											"image_tag":	repository_tag,
											"last_updated":	last_updated,
											"created":		created
									 })
			else:
				#-- The image has already been retrieved via another tag (i.e. the image has multiple tags)
				logging.info("%s already retrieved for %s", fs_layer_ids, image_name)

	return images


def get_layers_verified_repository(repository):
	"""
		Retrieves all the layers, tags, creation dates and last updated times of all the images in the passed Verified repository.


		Note:
			All the tagged images in the passed repository are downloaded, as a simple retrieval of all the tags in a Verified repository is not possible through Docker Hub's API.
			The downloaded images are removed when this function returns.


		Args:
			repository	(string):	the name of the Verified repository to be retrieved


		Returns:
			list: 	a list of dictionaries containing successfully retrieved images from the passed repository

	"""
	images             = []
	retrieved_images   = dict()		#-- the images that have been retrieved so far
	fs_layer_ids       = ""			#-- the tagged image's combination of all layers
	retrials           = 3 + 2 		#-- number of times to retry retrieving on failure
	retrials_wait_time = 10  		#-- number of seconds to wait between failed retrieval retrials

	logging.info("Retrieving all tags in repository: %s", repository)

	for retrial in range(1, retrials):
		#-- Retrieving all the tagged images' FS layer ids in the passed repository
		try:
			client = docker.APIClient(base_url = "unix://var/run/docker.sock", timeout = 1800)
			client.login(dockerhub_username, dockerhub_password, reauth = True)
			tag    = ""

			total, used, free    = shutil.disk_usage(os.path.abspath(os.sep))
			disk_usage_threshold = free * 0.8

			for line in client.pull(repository = repository, stream = True, decode = True):
				#-- Streaming the image's pulling action in real time
				if re.search("Pulling from", str(line.get("status"))):
					#-- Retrieving the tag of the image to be analyzed
					tag = line.get("id")
					logging.info("Retrieving %s", repository + ":" + tag)


				elif line.get("status") == "Pulling fs layer" or line.get("status") == "Already exists":
					#-- Retrieving one layer
					fs_layer_ids += line.get("id")

				elif line.get("error"):
					#-- Retrieving failed for misc reason without throwing an explicit error (e.g. incompatible platform, gateway timeout, etc.)
					fs_layer_ids = ""

					if re.search("cannot be used on this platform", str(line.get("error"))) or re.search("no matching manifest", str(line.get("error"))) and re.search("microsoft", repository) or re.search("no matching manifest", str(line.get("error"))):
						#-- Incompatible platform
						raise docker.errors.APIError("cannot be used on this platform")

					else:
						#-- Misc reason without throwing an explicit error (e.g. gateway timeout, etc.)
						raise docker.errors.APIError("")

				elif re.search("Digest", str(line.get("status"))):
					#-- All the layers have been retrieved
					if fs_layer_ids:
						#-- Retrieving the downloaded image itself
						logging.info("Retrieved: %s", fs_layer_ids)

						for i in range(3):
							time.sleep(retrials_wait_time)								#-- gives powerful machines time to index the new downloaded image
							client = docker.from_env(timeout = 1800)
							image  = client.images.list(repository + ":" + tag)

							if image:
								break

						if not image:
							#-- The image is not indexed by the Docker Engine for misc reasons
							raise docker.errors.APIError("")

						image                                    = image[0]
						index                                    = image.attrs.get("Created").index(".")
						utc_time                                 = time.strptime(image.attrs.get("Created")[:index], "%Y-%m-%dT%H:%M:%S")
						image_created_time                       = calendar.timegm(utc_time)  # -- utc epoch timestamp
						retrieved_images[repository + ":" + tag] = image.id.split(":")[1]

						images.append({
											"fs_layers": 	fs_layer_ids,
											"image_tag": 	tag,
											"last_updated": image.history()[0].get("Created"),
											"created":		image_created_time
									 })

						#-- Deleting images in the current repository being populated in order to free disk space
						total, used, free = shutil.disk_usage(os.path.abspath(os.sep))

						if used >= disk_usage_threshold:
							undeleted = dict()

							for image_name, image_id in retrieved_images.items():
								logging.info("Deleting: " + image_name)

								if not image_analyzer.remove_image(image_id):
									undeleted[image_name] = image_id

							retrieved_images = undeleted

					else:
						#-- The image has already been retrieved
						logging.info("Layers already retrieved for %s", repository)

					fs_layer_ids = ""

			break

		except docker.errors.APIError as e:
			if re.search("cannot be used on this platform", str(e)):
				#-- Incompatible platform
				logging.info("Incompatible platform for repository: %s", repository)
				break

			elif re.search("docker login", str(e)):
				#-- The image has not been checked out or the login may have failed
				logging.warning("Docker login required for repository: %s", repository)

			else:
				#-- Retrieving failed for misc reason (e.g. internal server error, busy server, failed login etc.)
				logging.warning("Image retrieval failed")
				images       = []
				fs_layer_ids = ""

			if retrial < retrials - 1:
				time.sleep(retrials_wait_time)
				logging.info("Retrying to retrieve all images in %s [%s/%s] ...", repository, str(retrial), str(retrials - 2))
				continue

	#-- Removing downloaded images
	retrs = 4

	for image_name, image_id in retrieved_images.items():
		logging.info("Deleting: " + image_name)

		for retrial in range(1, retrs):
			if image_analyzer.remove_image(image_id):
				break
			else:
				logging.warning("Image deletion failed")
				logging.info("Retrying to delete %s [%s/%s]", image_name, str(retrial), str(retrs))

	return images


def update_official_database(db_file):
	"""
		Verifies whether some repositories in the passed parent database file contain images which have been updated on Docker Hub and updates them.


		Note:
			Brand new images that have emerged in a repository consist of the combination of both a new tag and a new bottom layer.


		Args:
			db_file		(string): 	the absolute path to the parent database file to ...


		Returns:
			None

	"""
	try:
		new_repositories = dockerhub_api.get_official_images()
		parent_db        = dict()

		with open(db_file, "r") as json_file:
			parent_db = json.loads(json_file.readline())

		if not new_repositories:
			msg = "Official repositories could not be retrieved from Docker Hub!"
			logging.critical(msg)
			print(msg)
			print("Exiting ...")
			os._exit(0)


		#-- Verify whether new repositories have come up since the last update
		if len(new_repositories) > len(parent_db.keys()):
			#-- New repositories have come up on Docker Hub since the last database update
			new_repositories = [repo.get("name") for repo in new_repositories]
			new_repositories = list(set(new_repositories) - set(parent_db.keys()))		#-- brand new repositories having appeared on the public registry

			logging.info("New repositories have emerged: " + ", ".join(new_repositories))

			for new_repository in new_repositories:
				repository_images = get_layers_official_repository(new_repository)

				if repository_images:
					#-- Writing the gathered images in the current repository to file
					dict_element = {new_repository: repository_images}
					utils.write_dict_element_to_file(dict_element, db_file)

					#-- Updating the database loaded to memory
					parent_db[new_repository] = repository_images
		else:
			logging.info("No new repository has emerged")


		#-- Verify whether each repository has been updated since it was last grabbed
		for repository in list(parent_db.keys()):
			logging.info("Checking " + repository + " ...")

			result = dockerhub_api.get_repository_tags_query_v2("library/" + repository)
			tag    = dockerhub_api.get_latest_versioned_tag("library/" + repository)
			result = dockerhub_api.get_repository_tag_query_v2("library/" + repository, tag)

			if result is not None:
				utc_time          = time.strptime(result.get("last_updated"), "%Y-%m-%dT%H:%M:%S.%fZ")
				new_updated_time  = calendar.timegm(utc_time)  							#-- utc epoch timestamp
				last_updated_time = 0													#-- the first image of each repository in the database is not necessarily the last updated one
				threshold         = 30
				n                 = 0

				for image in parent_db[repository]:
					if n >= threshold:
						#-- The remaining images in the repository are too old
						break

					if image.get("last_updated") > last_updated_time:
						last_updated_time = image.get("last_updated")
					else:
						n += 1

				if new_updated_time > last_updated_time:
					#-- Some images in the repository have been updated or new ones have emerged
					logging.info("Images have emerged or have been updated in the repository: " + repository)

					new_repository_tags   = dockerhub_api.get_repository_tags_query_v2("library/" + repository)
					repository_images     = parent_db[repository]
					added_image_layers    = set()					#-- the new image layers gathered for the 'repository' during its update
					non_updated_threshold = 30  					#-- the maximum number of processed images which have not been updated to be reached before skipping the rest of the repository
					n                     = 0  						#-- the current number of processed images which have not been updated

					for new_repository_tag in new_repository_tags:
						#-- Verifying whether the image is brand new or has been updated
						if n >= non_updated_threshold:
							#-- The remaining images are too old to have been updated
							break

						new_image_layers = get_layers_image(repository, new_repository_tag)
						is_image_updated = False

						if new_image_layers:
							for repository_image in repository_images:
								is_in_db = False

								if repository_image.get("fs_layers") == new_image_layers:
									#-- The image exists in the database and should not need to be updated (its timestamp may)
									result = dockerhub_api.get_repository_tag_query_v2("library/" + repository, new_repository_tag)

									if result is not None and result.get("last_updated") != "null" and result.get("last_updated") is not None:
										utc_time         = time.strptime(result.get("last_updated"), "%Y-%m-%dT%H:%M:%S.%fZ")
										new_updated_time = calendar.timegm(utc_time)  												#-- utc epoch timestamp

										if new_updated_time > repository_image.get("last_updated"):
											#-- The image has a tag with a newer last updated timestamp
											logging.info("Updating image's timestamp: " + repository + ":" + new_repository_tag)

											image_index = repository_images.index(repository_image)
											parent_db[repository][image_index]["last_updated"] = new_updated_time

									is_image_updated  = True
									n                += 1

								elif repository_image.get("image_tag") == new_repository_tag:
									#-- The tag exists in the database but has another signature (the image has been updated)
									if new_image_layers in added_image_layers:
										#-- The image's signature has just been added through another tag and the current image should be removed from the database to avoid duplicates
										parent_db[repository].remove(repository_image)
										continue

									result = dockerhub_api.get_repository_tag_query_v2("library/" + repository, new_repository_tag)

									if result is not None and result.get("last_updated") != "null" and result.get("last_updated") is not None:
										utc_time          = time.strptime(result.get("last_updated"), "%Y-%m-%dT%H:%M:%S.%fZ")
										new_updated_time  = calendar.timegm(utc_time)  												#-- utc epoch timestamp

										logging.info("Updating image: " + repository + ":" + new_repository_tag)

										image_index                                        = repository_images.index(repository_image)
										parent_db[repository][image_index]["fs_layers"]    = new_image_layers
										parent_db[repository][image_index]["last_updated"] = new_updated_time
										is_image_updated                                   = True
										added_image_layers.add(new_image_layers)

							if not is_image_updated and new_image_layers not in added_image_layers:
								#-- The image is brand new
								logging.info("Adding new image: " + repository + ":" + new_repository_tag)

								result = dockerhub_api.get_repository_tag_query_v2("library/" + repository, new_repository_tag)

								if result is not None and result.get("last_updated") != "null" and result.get("last_updated") is not None:
									utc_time     = time.strptime(result.get("last_updated"), "%Y-%m-%dT%H:%M:%S.%fZ")
									updated_time = calendar.timegm(utc_time)  																	#-- utc epoch timestamp
									result       = microbadger_api.get_repository_tag_query_v1("library/" + repository,new_repository_tag)

									if result:
										utc_time = time.strptime(result.get("Created"), "%Y-%m-%dT%H:%M:%S.%fZ")
										created = calendar.timegm(utc_time)

										parent_db[repository].append({
																			"fs_layers": 		new_image_layers,
																			"image_tag": 		new_repository_tag,
																			"last_updated": 	updated_time,
																			"created": 			created
																	})

										added_image_layers.add(new_image_layers)
				else:
					logging.info("Repository up to date")


			#-- Writing the results back to the passed parent database file
			with open(db_file, "w") as json_file:
				json_file.write(json.dumps(parent_db))


		#-- Renaming the passed file with the updated timestamp
		current_date_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
		timestamp         = re.search("[\d\-]+_[\d\-]+", db_file).group(0)
		new_db_file       = db_file.replace(timestamp, current_date_time)

		os.rename(db_file, new_db_file)

	except:
		logging.exception("Failed to read parent_db Json file")


def update_verified_database(db_file):
	"""
		Verifies whether some repositories in the passed parent database file contain images which have been updated on Docker Hub and updates them.


		Note:
			Brand new images that have emerged in a repository consist of the combination of both a new tag and a new bottom layer.


		Args:
			db_file		(string): 	the absolute path to the parent database file to ...


		Returns:
			None

	"""
	try:
		new_repositories = dockerhub_api.get_verified_images() + dockerhub_api.get_certified_images()
		parent_db        = dict()

		with open(db_file, "r") as json_file:
			parent_db = json.loads(json_file.readline())

		if not new_repositories:
			msg = "Verified repositories could not be retrieved from Docker Hub!"
			logging.critical(msg)
			print(msg)
			print("Exiting ...")
			os._exit(0)


		#-- Verify whether new repositories have come up since the last update
		if len(new_repositories) > len(parent_db.keys()):
			#-- New repositories have come up on Docker Hub since the last database update
			new_repos = [repo.get("name") for repo in new_repositories]
			new_repos = list(set(new_repos) - set(parent_db.keys()))			#-- brand new repositories having appeared on the public registry

			logging.info("New repositories have emerged: " + ", ".join(new_repos))

			excluded_repositories = ["store/saplabs/hanaexpressxsa", "store/ibmcorp/db2wh_ce", "store/ibmcorp/db2wh_ee"]

			for new_repo in new_repos:
				if new_repo in excluded_repositories:
					continue

				repository_images = get_layers_verified_repository(new_repo)

				if repository_images:
					#-- Writing the gathered images in the current repository to file
					dict_element = {new_repo: repository_images}
					utils.write_dict_element_to_file(dict_element, db_file)

					#-- Updating the database loaded to memory
					parent_db[new_repo] = repository_images

				else:
					logging.info("Could not retrieve repository: " + new_repo)
		else:
			logging.info("No new repository has emerged")


		#-- Verify whether each repository has been updated since it was last grabbed
		for repository in list(parent_db.keys()):
			logging.info("Checking " + repository + " ...")

			repository_slug_name = ""

			#-- Retrieving the repository's slug name
			for new_repository in new_repositories:
				if repository == new_repository.get("name"):
					repository_slug_name = new_repository.get("slug_name")

			if repository_slug_name:
				result = dockerhub_api.get_repository_query_v1(repository_slug_name)

				if not result.get("message"):
					#-- Retrieving the repository's latest tag
					latest_tag   = ""

					if re.search("microsoft", repository):
						#-- Microsoft specific retrieval
						description = result.get("full_description")
						latest_tag  = re.search("docker pull.*?:([.\w\d:-]+)", description)  			#-- e.g. '1.0', 'v1.2.3-alpine'

						if latest_tag:
							latest_tag = latest_tag.group(1)

						else:
							logging.warning("The latest tag could not be retrieved for the repository: " + repository)
							logging.info("Defaulting to the 'latest' tag")
							latest_tag = "latest"
					else:
						#-- Normal retrieval
						default_plan    = result.get("plans")[0]
						default_version = default_plan.get("versions")[0]
						latest_tag      = default_version.get("tags")[0].get("value") if default_version.get("tags")[0].get("value") else "latest"

					new_image_layers = get_layers_image(repository, latest_tag)

					if new_image_layers:
						is_in_db   = False
						is_updated = True

						for image in parent_db[repository]:
							if image.get("image_tag") == latest_tag:
								#-- The latest image is in the database (not new)
								is_in_db = True

							elif image.get("fs_layers") == new_image_layers:
								#-- The latest image is in the database with another tag (the image is up to date)
								is_in_db = True

						if not is_in_db:
							#-- The repository has been updated, re-downloading all the images in the repository
							logging.info("Images have been updated in repository: " + repository)

							parent_db[repository] = get_layers_verified_repository(repository)


							#-- Writing the results back to the passed parent database file
							with open(db_file, "w") as json_file:
								json_file.write(json.dumps(parent_db))

						else:
							logging.info("Repository up to date")

					else:
						logging.warning("Could not retrieve the bottom layer for: " + repository + ":" + latest_tag)


		#-- Renaming the passed file with the updated timestamp
		current_date_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
		timestamp         = re.search("[\d\-]+_[\d\-]+", db_file).group(0)
		new_db_file       = db_file.replace(timestamp, current_date_time)

		os.rename(db_file, new_db_file)

	except:
		logging.exception("Failed to read parent_db Json file")


def verify_duplicates(db_file):
	"""
		Controlling function verifying whether there are duplicates between multiple repositories.


		Args:
			db_file	(string): the absolute path the parent database file to be processed


		Returns:
			None

	"""
	print (db_file)

	try:
		db_type = "official" if re.search("official", db_file) else "verified"

		with open(db_file, "r") as json_file:
			parent_db = json.loads(json_file.readline())

		for repository, images in parent_db.items():
			for image in images:
				#-- Trying to find an identical 'image' in other 'repositories'
				repositories  = list(parent_db.keys())
				repositories  = repositories[:repositories.index(repository)] + repositories[repositories.index(repository) + 1:]  	#-- excluding 'repository' from the list of 'repositories'

				for repo in repositories:
					is_image_parent = True  	#-- whether the image that is being checked in other repositories seems to be a parent

					for img in parent_db[repo]:
						if image.get("fs_layers") == img.get("fs_layers"):
							#-- The images are identical, the oldest image is the legitimate parent
							logging.info("Resolving duplicates between " + repository + ":" + image.get("image_tag") + " and " + repo + ":" + img.get("image_tag") + " - " + image.get("fs_layers"))


							print ("Resolving duplicates between " + repository + ":" + image.get("image_tag") + " and " + repo + ":" + img.get("image_tag") + " - " + image.get("fs_layers"))
							print (repository + ": " + str(image.get("created")))
							print (repo       + ": " + str(img.get("created")))


							if image.get("created") - img.get("created") > 0:
								# -- 'image' is more recent than 'img'
								#parent_db[repository].remove(image)
								is_image_parent = False
							else:
								# -- 'image' is older than 'img'
								#parent_db[repo].remove(img)
								pass

					if not is_image_parent:
						#-- 'image' was not a parent image and has been removed
						break


		#with open(db_file, "w") as json_file:
		#	json_file.write(json.dumps(parent_db))

	except:
		logging.exception("Failed to read parent_db Json file")


def main ():
	"""
		The software's main thread responsible for gathering the very last layer of all the images present in each repository of the passed type and exports them to a Json file.


		Returns:
			None

	"""
	#-- Requirement verification
	init()


	#-- Logging initialization
	current_date_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
	home              = os.path.dirname(os.path.realpath(__file__))
	log_dir           = os.path.join(home, "DAZER/log")

	if not os.path.exists(log_dir):
		os.mkdir(log_dir)

	log_file = os.path.join(log_dir, "logging_parent_db_" + current_date_time + ".log")

	logging.basicConfig(filename = log_file, level = logging.INFO, format = "%(asctime)s %(message)s", datefmt = "%Y-%m-%d %H:%M:%S")
	print("Note: see the log file for more information.")


	#-- Input validation & Parent database existence verification
	arguments     = validate_input()
	home          = os.path.dirname(os.path.realpath(__file__))
	parent_db_dir = os.path.join(home, "DAZER/json/parent_db")
	repositories  = []
	official_db   = ""
	verified_db   = ""

	if os.path.exists(parent_db_dir):
		#-- The parent database file may exist
		if arguments.type == "official":
			official_dbs = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(official)", resource)]
			official_db  = utils.get_most_recent_file(official_dbs)

		elif arguments.type == "verified":
			verified_dbs = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(verified)", resource)]
			verified_db  = utils.get_most_recent_file(verified_dbs)

		else:
			print("Wrong argument. Run ./main.py -h for more information")
			os._exit(0)
	else:
		#-- The parent database file does not exist
		logging.info("No %s database has been found so it will be populated from scratch", str(arguments.type).capitalize())
		os.makedirs(parent_db_dir)


	#-- Database file initialization
	db_file     = ""
	is_updating = False

	if arguments.type == "official" and official_db:
		#-- Updating the Official parent database
		logging.info("The %s database already exists and will be updated", str(arguments.type).capitalize())
		db_file     = official_db
		is_updating = True

	elif arguments.type == "verified" and verified_db:
		#-- Updating the Verified parent database
		logging.info("The %s database already exists and will be updated", str(arguments.type).capitalize())
		db_file     = verified_db
		is_updating = True

	else:
		#-- Populating a parent database of the passed type from scratch
		db_file = os.path.join(parent_db_dir, "parent_db_" + arguments.type + "_" + current_date_time + ".json")

		with open(db_file, "a") as json_file:
			json_file.write("{}")


	#-- Updating or Populating the database of the passed type from scratch
	if is_updating:
		if arguments.type == "official":
			update_official_database(db_file)

		elif arguments.type == "verified":
			update_verified_database(db_file)

	else:
		if arguments.type == "official":
			logging.info("Retrieving Official repositories")
			repositories = dockerhub_api.get_official_images()

		elif arguments.type == "verified":
			logging.info("Retrieving Verified repositories")
			repositories = dockerhub_api.get_verified_images() + dockerhub_api.get_certified_images()

		if len(repositories) == 0:
			msg = arguments.type + " repositories could not be retrieved from Docker Hub!"
			logging.critical(msg)
			print(msg)
			print("Exiting ...")
			os._exit(0)
		else:
			logging.info("Total retrieved: " + str(len(repositories)))


		#-- Gathering unique FS layer id combinations for all the repositories of the passed type
		for repository in repositories:
			repository_name   = repository.get("name")
			repository_images = get_layers_official_repository(repository_name) if arguments.type == "official" else get_layers_verified_repository(repository_name)	#-- some repositories may only contain non-retrievable images (e.g. due to incompatible platform)

			if repository_images:
				#-- Writing the gathered images in the current repository to file
				dict_element = {repository_name: repository_images}
				utils.write_dict_element_to_file(dict_element, db_file)


if __name__ in "__main__":
	print ("Starting ...")

	main()

	print ("")
	print ("DONE!")