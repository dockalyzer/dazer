#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
	This module consists of the main module of the Docker vulnerability AnalyZER (DAZER) software and is responsible for following:

		1) Grabbing a list of the latest images of the passed type from Docker Hub's API (see the examples section for allowed image types)

		2) Starting a background thread for serially downloading the retrieved list of images from the Docker Hub registry

		3) Analyzing downloaded images periodically for metadata and vulnerability information gathering (see the note section for more information about vulnerability gathering)

		4) Exporting all gathered metadata information to a dedicated Json file

		5) Exporting all gathered vulnerability information to a dedicated Json file

		6) Logging normal and exceptional flow events along the way to a dedicated log file


	Note 1:
		The gathering of vulnerability information about downloaded images is executed through the use of Clair scanner.
		Clair scanner is an extension of the analyze-local-images tool by CoreOS, which enables quick analysis of local Docker images with the Clair software.
		Note that Clair is an open source project for the static analysis of vulnerabilities in application containers developed by CoreOS and verifies vulnerabilities
		against a dedicated database updated daily.


	Note 2:
		Since DAZER's goal is to be a simple tool for studying Docker Hub's security landscape, Community images are downloaded randomly among the most pulled images
		within that category, as they represent the highest risk of spreading vulnerabilities due to their popularity level.


	Examples:
		Gathering metadata and vulnerability information for all Certified images:

			./main.py certified

		Gathering metadata and vulnerability information for all Verified images:

			./main.py verified

		Gathering metadata and vulnerability information for all Official images:

			./main.py official

		Gathering metadata and vulnerability information for 100 random Community images among the most popular ones:

			./main.py community 100

"""


import argparse
import calendar
import datetime
import io
import json
import logging
import os
import populate_parent_db
import re
import shutil
import threading
import time

from DAZER import dockerhub_api
from DAZER import image_analyzer
from DAZER import initialization
from DAZER import utils


downloaded_image_layers = dict()	#-- the layer combination of each downloaded image


class DownloadingThread(threading.Thread):
	"""
		Thread subclass downloading the number of Docker images specified in the class' attribute on instantiation.


		Attributes:
			id						(int):		the thread's unique identification number
			name					(string):	the thread's name
			images					(list):		the list of images to be downloaded
			images_type				(string):	the type of images to be downloaded
			db_last_updated_time	(int):		the parent database(s)' last updated time
			verified_db				(string):	the absolute path to the verified parent database file
			disk_space_threshold	(int):		the disk space threshold pausing downloads once reached (consists of 60% of the machine's free disk space)

	"""
	
	def __init__(self, id, name, images, images_type, db_last_updated_time, verified_db, free_disk_space):
		"""
			Initiates the class' attributes on instantiation.


			Args:
				id						(int):		the thread's unique identification number
				name					(string):	the thread's name
				images					(list):		the list of images to be downloaded
				images_type				(string):	the type of images to be downloaded
				db_last_updated_time	(int):		the parent database(s)' last updated time
				verified_db				(string):	the absolute path to the verified parent database file
				free_disk_space			(int):		the machine's current free disk space in Bytes


			Returns:
				None

		"""
		threading.Thread.__init__(self)
		self.id                   = id
		self.name                 = name
		self.images               = images
		self.images_type		  = images_type
		self.db_last_updated_time = db_last_updated_time
		self.verified_db          = verified_db
		self.disk_space_threshold = free_disk_space * 0.6
		self.exit                 = False
		self.sleep_period         = 1.0
		self.stop_event           = threading.Event()
	
	def run(self):
		"""
			Represents the thread's activity.


			Returns:
				None
		"""
		logging.info("Starting " + self.name)
		
		retrials            = 3  		#-- number of times to retry downloading on failure
		retrials_wait_time  = 30  		#-- number of seconds to wait between failed download retrials
		disk_full_wait_time = 60 * 5	#-- number of seconds to wait once the disk space threshold has been reached

		if not self.exit and not self.stop_event.is_set():
			#-- The thread has not been requested to be stopped by the user (e.g. with CTRL+C)
			for image in self.images:
				while True:
					#-- Verifying whether the threshold for disk space usage has been reached
					current_images    = image_analyzer.scan_images()
					total_images_size = 0

					for current_image in current_images:
						total_images_size += int(current_image.attrs.get("Size"))

					if total_images_size >= self.disk_space_threshold:
						#-- The threshold has been reached
						logging.info("[%s] Pausing downloads temporarily to avoid reaching full disk usage", self.name)
						time.sleep(disk_full_wait_time)
					else:
						break

				#-- Verify whether the image has been updated since the last parent database update
				if self.images_type == "official" or self.images_type == "community":
					#-- Using the image's last updated timestamp from Docker Hub's v2 API
					result = dockerhub_api.get_repository_tag_query_v2("library/" + image.get("name"), image.get("tag")) if self.images_type == "official" else dockerhub_api.get_repository_tag_query_v2(image.get("name"), image.get("tag"))

					if result is not None and result.get("last_updated") is not None:
						utc_time           = time.strptime(result.get("last_updated"), "%Y-%m-%dT%H:%M:%S.%fZ")
						image_updated_time = calendar.timegm(utc_time)  											#-- utc epoch timestamp

						if image_updated_time > self.db_last_updated_time:
							#-- The image has been updated since the last parent database update and will be skipped
							logging.info("[%s] %s - Image download skipped (updated after the last parent database update)", self.name, image.get("name") + ":" + image.get("tag"))
							continue
					else:
						logging.info("[%s] %s - Image download skipped (updated after the last parent database update)", self.name, image.get("name") + ":" + image.get("tag"))
						continue

				elif self.images_type == "certified" or self.images_type == "verified":
					#-- Using the image's fs layer combination and its corresponding database
					image_layers = populate_parent_db.get_layers_image(image.get("name"), image.get("tag"))

					if image_layers:
						has_been_updated = True

						try:
							with open(self.verified_db, "r") as json_file:
								parent_db = json.loads(json_file.readline())

							repository_images = parent_db[image.get("name")]

							for repository_image in repository_images:
								if image_layers == repository_image.get("fs_layers"):
									has_been_updated = False
									break

						except IOError:
							logging.exception("Failed to read parent_db Json file")

						except KeyError:
							#-- Cannot check if the image has been updated
							logging.info("[%s] %s is not in DB SKIPPED!!", self.name, image.get("name") + ":" + image.get("tag"))
							continue

						if has_been_updated:
							#-- The image has been updated since the last parent database update and will be skipped
							logging.info("[%s] %s - Image download skipped (updated after the last parent database update)", self.name, image.get("name") + ":" + image.get("tag"))
							continue
					else:
						logging.info("[%s] %s - Image download skipped (could not retrieve the image's layers)", self.name, image.get("name") + ":" + image.get("tag"))
						continue

				else:
					#-- The image should be downloaded independently of its last updated time (e.g. a parent image)
					pass


				logging.info("[%s] Downloading %s ...", self.name, image.get("name") + ":" + image.get("tag"))
				
				try:
					#-- Downloading the image and retrieving its current layers
					image_layers                               = image_analyzer.download_image(image.get("name"), image.get("tag"))
					downloaded_image_layers[image.get("name")] = image_layers

					logging.info("[%s] Retrieved layers: %s", self.name, image_layers)

				except:
					#-- Download failed for misc reason (e.g. internal server error, failed login, image not found due to busy server, etc.)
					for retrial in range(1, retrials + 1):
						time.sleep(retrials_wait_time)
						
						try:
							logging.info("[%s] Retrying to download %s [%s/%s] ...", self.name, image.get("name") + ":" + image.get("tag"), str(retrial), str(retrials))
							image_analyzer.download_image(image.get("name"), image.get("tag"))
						except:
							#-- The download was a failure
							continue
						else:
							#-- The download was a success
							break
		
		self.stop_event.wait(self.sleep_period)
		logging.info("Exiting " + self.name)


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
		'requests==2.21.0',
		'docker==3.7.0',
		'speedtest-cli==2.0.2',
		'pyyaml==3.13'
	]
	non_installed_packages = initialization.verify_installed_packages(packages_required)
	
	if non_installed_packages:
		for package in non_installed_packages:
			print(package + " is either missing or does not satisfy the required version of this package")
		
		print("")
		print("You  may install all the required packages by DAZER using: 'pip3 install .'")
		print("Exiting ...")
		os._exit(0)


	#-- Ensuring that Clair DB is running
	if not image_analyzer.ensure_running_clair_db():
		print("Clair DB is not running and could not be started!")
		print("Exiting ...")
		os._exit(0)

	#-- Ensuring that Clair scanner is running
	if not image_analyzer.ensure_running_clair_scanner():
		print("Clair scanner is not running and could not be started!")
		print("Exiting ...")
		os._exit(0)


def validate_input():
	"""
		Ensures that the arguments passed to this script are valid to its requirements.


		Returns:
			None

	"""
	parser = argparse.ArgumentParser(
		description     = "DockAlyZER (DAZER) analyzes the passed type of Docker images for vulnerabilities and exports all the gathered information in JSON format "
	                      "for easy importation into the NOSQL database of your choice.\n"
	                      "DAZER supports the complete analysis of Official, Certified and Verified Docker images, as well as a subset of specified Community images.",
	    formatter_class = argparse.RawTextHelpFormatter
	)
	
	parser.add_argument(
		"type",
		default = ["official", "certified", "verified", "community"],
		nargs   = "?",
		help    = "Choose between 'official', 'certified', 'verified' or 'community'"
	)
	
	parser.add_argument(
		"size",
		type    = int,
		nargs   = "?",
		help    = "The subset of community images to analyze (e.g. 100)"
	)
	
	return parser.parse_args()


def clean_exit():
	"""
		Executes a exiting procedure removing eventual Docker images previously downloaded for a completely clean exit.

		Returns:
			None

	"""
	images = image_analyzer.scan_images()
	
	for image in images:
		image_analyzer.remove_image(image.id.split(":")[1])


def main():
	"""
		The software's main thread, responsible for following:

			1) Grabbing a list of the latest images of the passed type from Docker Hub's API

			2) Starting a background thread for serially downloading the retrieved list of images from the Docker Hub registry

			3) Analyzing downloaded images periodically for metadata and vulnerability information gathering

			4) Exporting all gathered metadata information to a dedicated Json file

			5) Exporting all gathered vulnerability information to a dedicated Json file

			6) Logging normal and exceptional flow events along the way to a dedicated log file


		Returns:
			None

	"""
	global downloading_thread

	try:
		#-- Requirement verification
		init()


		#-- Logging initialization
		current_date_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
		home              = os.path.dirname(os.path.realpath(__file__))
		log_dir           = os.path.join(home, "DAZER/log")
		
		if not os.path.exists(log_dir):
			os.mkdir(log_dir)
		
		log_file = os.path.join(log_dir, "logging_" + current_date_time + ".log")
		
		logging.basicConfig(filename = log_file, level = logging.INFO, format = "%(asctime)s %(message)s", datefmt = "%Y-%m-%d %H:%M:%S")


		#-- Input validation & Parent database verification
		arguments         = validate_input()
		experiment_type   = ""
		parent_db_dir     = os.path.join(home + "/DAZER/json/parent_db")
		official_db       = ""
		verified_db       = ""
		is_db_existing    = False

		if arguments.type == "official":
			official_dbs    = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(official)", resource)]
			official_db     = utils.get_most_recent_file(official_dbs)
			experiment_type = "official"

		elif arguments.type == "verified":
			official_dbs    = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(official)", resource)]
			verified_dbs    = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(verified)", resource)]
			official_db     = utils.get_most_recent_file(official_dbs)
			verified_db     = utils.get_most_recent_file(verified_dbs)
			experiment_type = "verified"

		elif arguments.type == "certified":
			official_dbs    = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(official)", resource)]
			verified_dbs    = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(verified)", resource)]
			official_db     = utils.get_most_recent_file(official_dbs)
			verified_db     = utils.get_most_recent_file(verified_dbs)
			experiment_type = "certified"

		elif arguments.type == "community" and arguments.size:
			official_dbs    = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(official)", resource)]
			official_db     = utils.get_most_recent_file(official_dbs)
			experiment_type = "community"

		else:
			print("Wrong argument. Run ./main.py -h for more information.")
			os._exit(0)

		if os.path.exists(parent_db_dir):
			if experiment_type == "certified" or experiment_type == "verified":
				if official_db and verified_db:
					is_db_existing = True
			else:
				#-- The conducted experiment is for 'official' or 'community' images
				if official_db:
					is_db_existing = True

		if not is_db_existing:
			print("A database file for image parent retrieval is required for running DAZER!")
			print("Run ./populate_parent_db.py -h for more information.")
			print("")
			print("Note: Certified and Verified experiments require both an Official and Verified parent database.")
			os._exit(0)


		#-- Parent database update
		logging.info("Updating Official parent database ...")
		populate_parent_db.update_official_database(official_db)
		official_dbs         = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(official)", resource)]
		official_db          = utils.get_most_recent_file(official_dbs)
		db_date              = official_db.split("_")[-2]
		db_time              = official_db.split("_")[-1].replace(".json", "")
		db_datetime          = db_date + "_" + db_time
		utc_time             = time.strptime(db_datetime, "%Y-%m-%d_%H-%M-%S")
		db_last_updated_time = calendar.timegm(utc_time)  							#-- utc epoch timestamp

		if experiment_type == "certified" or experiment_type == "verified":
			logging.info("Updating Verified parent database ...")
			populate_parent_db.update_verified_database(verified_db)
			verified_dbs = [os.path.join(parent_db_dir, resource) for resource in os.listdir(parent_db_dir) if re.search("(verified)", resource)]
			verified_db  = utils.get_most_recent_file(verified_dbs)
			db_date      = verified_db.split("_")[-2]
			db_time      = verified_db.split("_")[-1].replace(".json", "")
			db_datetime  = db_date + "_" + db_time
			utc_time     = time.strptime(db_datetime, "%Y-%m-%d_%H-%M-%S")
			utc_time     = calendar.timegm(utc_time)

			if utc_time < db_last_updated_time:
				db_last_updated_time = utc_time


		#-- Initial Docker Hub scraping
		images_to_analyze = []
		extra_images      = []

		if experiment_type == "official":
			logging.info("Retrieving Official images")
			images_to_analyze = dockerhub_api.get_official_images()

		elif experiment_type == "verified":
			logging.info("Retrieving Verified images")
			images_to_analyze = dockerhub_api.get_verified_images()
		
		elif experiment_type == "certified":
			logging.info("Retrieving Certified images")
			images_to_analyze = dockerhub_api.get_certified_images()
		
		elif experiment_type == "community" and arguments.size:
			logging.info("Retrieving %s Community images", str(arguments.size))
			images_to_analyze, extra_images = dockerhub_api.get_community_images(arguments.size)

		if len(images_to_analyze) == 0:
			msg = str(experiment_type).capitalize() + " images could not be retrieved from Docker Hub!"
			logging.critical(msg)
			print(msg)
			print("Exiting ...")
			os._exit(0)

		logging.info("Total retrieved: " + str(len(images_to_analyze)))
		print ("Note: see the log file for more information.")


		#-- Initializing the output file to be used during this experiment for image and vulnerability information
		json_dir = os.path.join(home, "DAZER/json")
		
		if not os.path.exists(json_dir):
			os.mkdir(json_dir)

		analysis_file      = os.path.join(json_dir, "analysis_"        + current_date_time + ".json")
		vulnerability_file = os.path.join(json_dir, "vulnerabilities_" + current_date_time + ".json")
		vulnerabilities    = []  #--------------------------------------------------------------------- list of all the discovered vulnerabilities

		with open(analysis_file, "w") as json_file:
			json_file.write("[]")

		with open(vulnerability_file, "w") as json_file:
			json_file.write("[]")


		#-- Starting the Downloading Thread
		total, used, free  = shutil.disk_usage(os.path.abspath(os.sep))
		downloading_thread = DownloadingThread(2, "Downloading Thread", images_to_analyze, experiment_type, db_last_updated_time, verified_db if verified_db else None, free)
		downloading_thread.daemon = True
		downloading_thread.start()


		#-- Scanning for new downloaded images periodically until the end of the Downloading tread
		periodic_wait_time = 60  	#-- number of seconds to wait between each scanning iteration
		continue_scanning  = 1      #-- number of times to scan once the downloading thread has ended (higher is safer and does not cost much performance)
		orphaned_images    = []     #-- list of ids for the images that could not be removed in the previous iteration
		parents            = []		#-- list of parents that have been identified and should be downloaded
		
		while downloading_thread.isAlive() or continue_scanning >= 0:
			#-- Ensuring that Clair DB and Clair scanner are running
			if not image_analyzer.ensure_running_clair_db() or not image_analyzer.ensure_running_clair_scanner():
				msg = "One of Clair's services could not be started!"
				logging.error(msg)
				print (msg)
				print ("Exiting ...")
				print ("")
				os._exit(0)
			
			analyzed_images     = []  	#-- list of dictionaries (Json objects) to be exported to a dedicated json file
			new_vulnerabilities = []  	#-- list of dictionaries (Json objects) to be exported to a dedicated json file

			#-- Checking for new downloaded images
			logging.info("Scanning for new downloaded images")
			images = image_analyzer.scan_images()


			if downloading_thread.isAlive() and len(images) == 0:
				#-- Giving time for the downloading thread to download images
				logging.info("Waiting for images to be downloaded")
				time.sleep(periodic_wait_time)
				continue


			if images:
				logging.info("%s new image(s) have been downloaded", str(len(images)))
				
				for image in images:
					image_name = str(image.tags[0]).split(":")[0]
					logging.info("Analyzing " + image_name)

					#-- Gathering basic information
					basic_info = image_analyzer.parse_basic_info(image)


					#-- Gathering complementary information parsed via Docker Hub's API
					extra_info = dict()
					image_type = dockerhub_api.get_repository_type(image_name)

					if not image_type:
						#-- The image is of type 'certified' or 'verified' and must use its slug name to interact with Docker Hub's  API
						for image_to_analyze in images_to_analyze:
							if image_to_analyze.get("name") == basic_info.get("name"):
								extra_info = dockerhub_api.get_image_extrainfo(image_to_analyze.get("slug_name"))
								break
					else:
						#-- The image is of type 'official' or 'community' and may use its usual name
						extra_info = dockerhub_api.get_image_extrainfo(image_name)


					#-- Gathering parental information
					image_parent       = ""
					image_parent_dict  = dict()
					image_layers       = downloaded_image_layers.get(basic_info.get("name"))
					retrials           = 3  	#-- number of times to retry downloading on failure
					retrials_wait_time = 30  	#-- number of seconds to wait between failed download retrials

					if image_layers:
						is_retrieved = False

						#-- Trying to retrieve the image's parent from the Official database (most likely for any type of image)
						try:
							image_parent_dict = dockerhub_api.get_image_parent(basic_info.get("name"), image_layers, "official")

							if image_parent_dict:
								image_parent = image_parent_dict.get("name") + ":" + image_parent_dict.get("tag")

							is_retrieved = True

						except:
							#-- The database file could not be read or is missing
							logging.exception("Failed to read parent_db Json file")

							for retrial in range(1, retrials + 1):
								time.sleep(retrials_wait_time)

								try:
									logging.info("Retrying to retrieve parent for %s [%s/%s] ...", basic_info.get("name") + ":" + basic_info.get("tag"), str(retrial), str(retrials))
									image_parent_dict = dockerhub_api.get_image_parent(basic_info.get("name"), image_layers, "official")

									if image_parent_dict:
										image_parent = image_parent_dict.get("name") + ":" + image_parent_dict.get("tag")

								except:
									#-- The retrieval was a failure
									logging.exception("Failed to read parent_db Json file")
									continue
								else:
									#-- The retrieval was a success
									is_retrieved = True
									break

						if not is_retrieved and experiment_type == "verified" or experiment_type == "certified":
							#-- Trying to retrieve the image's parent from the Verified database
							try:
								image_parent_dict = dockerhub_api.get_image_parent(basic_info.get("name"), image_layers, "verified")

								if image_parent_dict:
									image_parent = image_parent_dict.get("name") + ":" + image_parent_dict.get("tag")

								is_retrieved = True

							except:
								#-- The database file could not be read or is missing
								logging.exception("Failed to read parent_db Json file")

								for retrial in range(1, retrials + 1):
									time.sleep(retrials_wait_time)

									try:
										logging.info("Retrying to retrieve parent for %s [%s/%s] ...", basic_info.get("name") + ":" + basic_info.get("tag"), str(retrial), str(retrials))
										image_parent_dict = dockerhub_api.get_image_parent(basic_info.get("name"), image_layers, "verified")

										if image_parent_dict:
											image_parent = image_parent_dict.get("name") + ":" + image_parent_dict.get("tag")

									except:
										#-- The retrieval was a failure
										logging.exception("Failed to read parent_db Json file")
										continue
									else:
										#-- The retrieval was a success
										is_retrieved = True
										break
					else:
						logging.error("Could not retrieve layers for %s", basic_info.get("name") + ":" + basic_info.get("tag"))

					if image_parent_dict and image_parent_dict not in parents:
						parents.append(image_parent_dict)


					#-- Gathering vulnerability information
					exit_code, vuln_information, stderr = image_analyzer.analyze_image(basic_info.get("image_id"))
					error                               = (io.BufferedReader(stderr)).read()

					if re.search("CRIT", str(error)):
						#-- The image is not supported by Clair and will be removed
						if not image_analyzer.remove_image(basic_info.get("image_id")):
							#-- Adding to the list of orphaned images
							orphaned_images.append(basic_info.get("image_id"))
						
						logging.info("Image skipped (not supported by Clair)")
						continue

					image_vulnerabilities = [info.get("cve_number") for info in image_analyzer.parse_vulnerability_info(vuln_information)]


					#-- Updating the list of found vulnerabilities
					incoming_vulnerabilities = image_analyzer.parse_vulnerability_info(vuln_information)
					
					for incoming_vulnerability in incoming_vulnerabilities:
						is_already_found = False
						
						for vulnerability in vulnerabilities:
							if incoming_vulnerability.get("cve_number") == vulnerability.get("cve_number"):
								is_already_found = True
								break
						
						if not is_already_found:
							new_vulnerabilities.append(incoming_vulnerability)
							vulnerabilities.append(incoming_vulnerability)


					#-- Updating the list of analyzed images
					analyzed_images.append({
						"image_id":         		basic_info.get("image_id"),
						"type":             		extra_info.get("type"),
						"name":             		basic_info.get("name"),
						"tag":              		basic_info.get("tag"),
						"last_updated":     		basic_info.get("last_updated"),
						"total_pulled":     		extra_info.get("total_pulled"),
						"vulnerabilities":  		image_vulnerabilities,
						"total_vulnerabilities":	len(image_vulnerabilities),
						"parent":           		image_parent
					})


					#-- Deleting the analyzed image
					logging.info("Deleting " + image_name)
					if not image_analyzer.remove_image(basic_info.get("image_id")):
						#-- Adding to the list of orphaned images
						orphaned_images.append(basic_info.get("image_id"))


				#-- Deleting potentially left out images
				if orphaned_images:
					for image in orphaned_images:
						logging.info("Deleting orphaned " + image_name)
						image_analyzer.remove_image(image)  			#-- unsuccessfully deleted images will remain until the end of the experiment
					
					orphaned_images.clear()


				#-- Writing the gathered information to file to make sure everything is not only in memory until the end
				if analyzed_images:
					#-- At least one image has been successfully analyzed
					utils.write_dict_list_to_file(analyzed_images, analysis_file)

				if new_vulnerabilities:
					#-- At least one vulnerability has been found
					utils.write_dict_list_to_file(new_vulnerabilities, vulnerability_file)
					new_vulnerabilities.clear()

				logging.info("Analysis completed")
			else:
				logging.info("No new images have been downloaded")
			
			
			if not downloading_thread.isAlive():
				#-- All images have been downloaded
				if experiment_type is "community":
					#-- Verifying whether the number of analyzed images corresponds to the passed number by the user
					if not len(images) == 0:
						#-- Not all the downloaded images have been analyzed yet
						continue

					try:
						with open(analysis_file, "r") as file:
							analysis = file.readline()
						
						if analysis.count("image_id") < len(images_to_analyze):
							#-- Some images have been skipped and extra ones should be analyzed to match the user's requirements
							missing    = arguments.size - analysis.count("image_id")
							new_images = extra_images[:missing]
							
							del extra_images[:missing]
							logging.info("[" + str(missing) + "/" + str(arguments.size) + "] images have been skipped.")
							
							#-- Starting the Downloading Thread again
							total, used, free  = shutil.disk_usage(os.path.abspath(os.sep))
							downloading_thread = DownloadingThread(2, "Downloading Thread", new_images, experiment_type, db_last_updated_time, verified_db if verified_db else None, free)
							downloading_thread.daemon = True
							downloading_thread.start()
							
							continue
					except:
						logging.exception("Failed to read Json file")

				if parents:
					logging.info("Retrieving [" + str(len(parents)) + "] parents")

					#-- Starting the Downloading Thread again to download and analyze recognized parent images
					total, used, free         = shutil.disk_usage(os.path.abspath(os.sep))
					downloading_thread        = DownloadingThread(2, "Downloading Thread", parents, None, db_last_updated_time, verified_db if verified_db else None, free)
					downloading_thread.daemon = True
					downloading_thread.start()
					parents = []
					continue

				logging.info("All images have been downloaded")
				continue_scanning -= 1
		
	except KeyboardInterrupt:
		try:
			#-- Exiting the downloading thread
			downloading_thread.exit = True
			downloading_thread.stop_event.is_set()
			print ("CTRL+C detected!")
			print ("Aborting background processes (this may take a while) ...")
			downloading_thread.join(timeout = 1)
		
		except (NameError, KeyboardInterrupt):
			#-- Exiting the main thread
			print("Please wait ...")
		
		#-- Removing all downloaded Docker images on the local machine
		print ("Cleaning up ...")
		clean_exit()


if __name__ in "__main__":
	print ("DAZERing ...")
	main()
	print ("")
	print ("DAZERed!")
