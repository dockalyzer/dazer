# -*- coding: utf-8 -*-
"""
	This module contains functions related to the scanning, analysis and parsing of information related to Docker images.

"""


import docker
import logging
import os
import re
import subprocess
import yaml
import requests

from DAZER import utils
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


#-- Credentials
dockerhub_username = ""
dockerhub_password = ""


#-- Initializing credentials
try:
	home             = os.path.dirname(os.path.realpath(__file__))
	credentials_file = os.path.join(home, "credentials.yml")
	
	with open(credentials_file, "r") as ymlfile:
		config_file = yaml.load(ymlfile)
	
	dockerhub_username = config_file["dockerhub_api"].get("username")
	dockerhub_password = config_file["dockerhub_api"].get("password")

except:
	logging.exception("Failed to open " + credentials_file)


def download_image(name, tag):
	"""
		Downloads the Docker image with the passed name and tag from Docker Hub and returns its fs layer combination.


		Args:
			name	(string):	the name of the image to be downloaded
			tag		(tag):		the tag of the image to be downloaded


		Returns:
			string:		the fs layer combination of the downloaded image


		Raises:
			docker.errors.APIError:		on download or interaction failure with the Docker Engine

	"""
	fs_layer_ids = ""  		#-- the tagged image's combination of all layers

	try:
		client = docker.APIClient(base_url = "unix://var/run/docker.sock", timeout = 1800)		#-- Docker daemon client (low-api)
		client.login(dockerhub_username, dockerhub_password, reauth = True)

		for line in client.pull(repository = name, tag = tag, stream = True, decode = True):
			#-- Streaming the image's pulling action in real time
			if line.get("status") == "Pulling fs layer" or line.get("status") == "Already exists":
				#-- Retrieving one layer
				fs_layer_ids += line.get("id")


	except docker.errors.APIError as e:
		if re.search("pull access denied", str(e)):
			#-- Download failed due to non checked out image
			logging.warning(name + ":" + tag + " - Image download skipped (requires checkout)")

		elif not re.search("manifest.*not found", str(e)):
			#-- Download failed for misc reason (e.g. internal server error, failed login, image not found due to busy server, etc.)
			logging.warning(name + ":" + tag + " - Image download failed")
			raise

		elif re.search("manifest.*not found", str(e)):
			if re.search("mcr\.microsoft\.com", str(e)):
				#-- Download failed due to wrong platform
				logging.info(name + ":" + tag + " - Image download skipped (incompatible platform)")
			else:
				#-- Download failed for misc reason as above, or due to indexed but non-valid image on Docker Hub (e.g. store/portworx/px-dev)
				logging.warning(name + ":" + tag + " - Image download failed")
				raise

		else:
			logging.exception("Failed to interact with the Docker Engine (high-level API)")

	return fs_layer_ids


def scan_images():
	"""
		Scans for new downloaded Docker images by interacting with the Docker Engine.


		Returns:
			list: 	a list of Image objects corresponding to new downloaded Docker images

	"""
	current_images = []
	
	try:
		client = docker.from_env(timeout = 1800)  #--------------------- Docker daemon client
		images = client.images.list()
		excluded_images = [
			"arminc\/clair-db:latest",
			"arminc\/clair-local-scan:latest"
		]  #------------------------------------------------- images to be excluded (i.e. related to Clair and Redash)
		
		for image in images:
			is_excluded = False
			
			for excluded_image in excluded_images:
				if re.search(excluded_image, image.tags[0]):  #-- the first image tag is sufficient (e.g. "(repo)/image-name:tags")
					is_excluded = True
					break
			
			if not is_excluded:
				current_images.append(image)
	
	except docker.errors.APIError:
		logging.exception("Failed to interact with the Docker Engine (high-level API)")
	
	return current_images


def parse_basic_info(image):
	"""
		Parses basic information (image id, name, tag and last updated time) from the passed Docker image and returns
		a dictionary with the parsed information.


		Args:
			image 	(Image): 	the Docker image object to be parsed


		Returns:
			dict: 	a dictionary containing the parsed information from the passed Docker image

	"""
	return {
		"image_id": 		image.id.split(":")[1],
		"name": 			str(image.tags[0]).split(":")[0],
		"tag": 				str(image.tags[0]).split(":")[1],
		"last_updated": 	image.history()[0].get("Created")
	}


def get_cwe(cve_number):
	"""
		Retrieves the Common Weakness Enumeration (CWE) number for the passed Common Vulnerabilities and Exposures (CVE) number.


		Note:
			Some CVEs returns null. They will be marked as "unknown".


		Args:
			cve_number (string):	the CVE number to be translated into a CWE id


		Returns:
			cwe_number (string):   the CWE number matching the passed CVE number

	"""
	cwe_number  = ''
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	cve_api     = 'https://cve.circl.lu/api/cve/'
	request     = cve_api + cve_number
	response    = requests.get(request, headers=headers)
	unknown_cwe = 'Unknown'
	
	#-- Retrying the request three times before an exception raises
	session = requests.Session()
	retries = Retry(connect=3, backoff_factor=30)
	adapter = HTTPAdapter(max_retries=retries)
	session.mount('http://', adapter)
	session.mount('https://', adapter)

	try:
		session.get(request)
		
		if response.ok:
			if response.text == 'null':
				#-- The CVE number does not figure in NVD's database and its CWE number will be marked as "Unknown"
				cwe_number = unknown_cwe

			elif response.json().get('cwe'):
				#-- The CVE number figures in NVD's database and has a matching CWE number
				cwe_number = response.json().get('cwe')

			else:
				#-- The CVE number figures in NVD's database but does not have a matching CWE number
				cwe_number = unknown_cwe

		else:
			logging.error(cve_number + ' - request to CVE API version failed (change in the API?)')
	
	except:
		logging.exception("Error for request: " + request)

	return cwe_number


def parse_vulnerability_info(vuln_information):
	"""
		Parses all the vulnerability information from the passed list of bytes into a dictionary.


		Args:
			vuln_information 	(list): 	the byte list of vulnerability information to be parsed


		Returns:
			list: 	a list of dictionaries containing all the vulnerability information parsed from the passed list of bytes

	"""
	vulnerabilities = []
	
	for line in vuln_information:
		if re.search("(Unapproved|Approved)", line.decode("utf-8")):
			#-- Contains valuable information
			info = line.decode("utf-8").split(" | ")[1:-1]  #------------ status & cve description not needed
			
			if len(info) == 3:
				vulnerabilities.append({
					"cve_number":	 	info[0].strip().split()[1],
					"cwe_number":       get_cwe(info[0].strip().split()[1]),
					"severity": 		info[0].strip().split()[0],
					"package_name": 	info[1].strip(),
					"package_version": 	info[2].strip()
				})
			else:
				#-- The vulnerability report has the wrong format
				logging.warning("Wrong format for the vulnerability report from Clair scanner (changed in Clair-scanner?)")
	
	return vulnerabilities


def analyze_image(image_id):
	"""
		Executes a vulnerability analysis of the Docker image with the passed id using Clair scanner.


		Args:
			image_id 	(string):	the id of the Docker image to be analyzed


		Returns:
			list 		(bytes): 	the unparsed vulnerability information gathered from the image with the passed id

	"""
	cmd  = os.path.expandvars("$HOME") + "/clair-scanner --ip " + utils.get_host_primary_ip() + " " + image_id
	proc = subprocess.Popen(cmd.split(), stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)
	
	return proc.returncode, proc.stdout.readlines(), proc.stderr


def remove_image(image_id):
	"""
		Removes the Docker image with the passed id.


		Args:
			image_id 	(string):  	the id of the Docker image to be removed


		Returns:
			bool: 	True if the removal was successful, False otherwise

	"""
	try:
		client = docker.APIClient(base_url = "unix://var/run/docker.sock", timeout = 3600)  #-- Docker daemon client (low-level API)
		client.remove_image(image_id, force = True)
	
	except:
		logging.exception("Failed to interact with the Docker Engine (low-level API)")
		return False
	
	return True


def ensure_running_clair_db():
	"""
		Ensures that the Clair database is up and running in a container, by downloading and starting it if necessary.


		Returns:
			bool:	True if the container is successfully running, False otherwise

	"""
	is_running = False
	
	try:
		client = docker.from_env(timeout = 1800)
		db     = client.containers.list(filters = {"name": "db"})
		
		if not db:
			#-- The container is not running
			db = client.containers.list(all = True, filters = {"name": "db"})
			
			if db:
				#-- Starting the container
				print ("Clair DB is not running and will be started (this may take a while) ...")
				db[0].start()
				is_running = True
			else:
				#-- The container has never been instantiated
				db_image = client.images.list("arminc/clair-db:latest")
				
				if db_image:
					#-- Running the container
					print("Clair DB is not running and will be started (this may take a while) ...")
					client.containers.run("arminc/clair-db:latest", name = "db", ports = {"5432/tcp": 5432}, detach = True)
					is_running = True
				else:
					#-- The image does not exist on this machine
					print("The Clair DB image is missing and will be downloaded then started (this may take a while) ...")
					download_image("arminc/clair-db", "latest")
					
					if client.images.list("arminc/clair-db:latest"):
						client.containers.run("arminc/clair-db:latest", name = "db", ports = {"5432/tcp": 5432}, detach = True)
						is_running = True
		else:
			is_running = True
	
	except docker.errors.APIError:
		logging.exception("Failed to interact with the Docker Engine (high-level API)")
	
	return is_running


def ensure_running_clair_scanner():
	"""
		Ensures that the Clair scanner server is up and running in a container, by downloading and starting it if necessary.


		Returns:
			bool:	True if the container is successfully running, False otherwise

	"""
	is_running = False
	
	try:
		client = docker.from_env(timeout = 1800)
		clair_scanner = client.containers.list(filters = {"name": "clair"})
		
		if not clair_scanner:
			#-- The container is not running
			clair_scanner = client.containers.list(all = True, filters = {"name": "clair"})
			
			if clair_scanner:
				#-- Starting the container
				print("Clair scanner is not running and will be started (this may take a while) ...")
				clair_scanner[0].start()
				is_running = True
			else:
				#-- The container has never been instantiated
				clair_scanner_image = client.images.list("arminc/clair-local-scan:latest")
				
				if clair_scanner_image:
					#-- Running the container
					print("Clair scanner is not running and will be started (this may take a while) ...")
					client.containers.run("arminc/clair-local-scan:latest", name = "clair", ports = {"6060/tcp": 6060}, links = {"db": "postgres"}, detach = True)
					is_running = True
				else:
					#-- The image does not exist on this machine
					print("The Clair scanner image is missing and will be downloaded then started (this may take a while) ...")
					download_image("arminc/clair-local-scan", "latest")
					
					if client.images.list("arminc/clair-local-scan:latest"):
						client.containers.run("arminc/clair-local-scan:latest", name = "clair", ports = {"6060/tcp": 6060},links = {"db": "postgres"}, detach = True)
						is_running = True
		else:
			is_running = True
	
	except docker.errors.APIError as e:
		if not re.search("ImageNotFound", str(e)):
			logging.exception("Failed to interact with the Docker Engine (high-level API)")
	
	return is_running
