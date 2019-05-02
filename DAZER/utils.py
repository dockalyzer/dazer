# -*- coding: utf-8 -*-
"""
	This module contains miscellaneous utility functions.

"""


import json
import logging
import os
import socket
import speedtest


def get_host_primary_ip():
	"""
		Obtains the primary IP address of the machine running this script.
		Note that a machine's primary IP address is the one with a default route.


		Returns:
			string:		the primary IP address of the machine running this script

	"""
	ip = ""
	s  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	try:
		s.connect(('10.255.255.255', 1))
		ip = s.getsockname()[0]

	except:
		logging.error("Failed to acquire primary IP address!")

	finally:
		s.close()

	return ip


def get_downloading_speed():
	"""
		Calculates the downloading speed in bit per second of the host running this script.


		Returns:
			int:	the host's downloading speed in bit/s

	"""
	s = speedtest.Speedtest()
	s.get_best_server()

	return s.download()


def calculate_downloading_time(size):
	"""
		Calculates the total amount of time in seconds for the host running this script to download a resource of the passed size.


		Args:
			size 	(int):	the size to be used for calculating the downloading time in bits


		Returns:
			int:	the number of seconds to download a resource of the passed size

	"""
	return size / get_downloading_speed()


def estimate_experiment_duration(avg_image_size, number_of_images):
	"""
		Estimates the approximate time for an experiment to execute based on the passed number of images and their average size.

		Note that the most time consuming task of an experiment is by far the download of Docker images, which is therefore the 
		preferred metric in order to estimate the total time of an experiment.


		Args:
			avg_image_size 		(int): 	the average size in MB (MegaBytes) of a Docker image
			number_of_images 	(int):	the total number of images to be downloaded during the experiment


		Returns:
			None

	"""
	mb_to_bit          = 10 ** 6						#-- MB (MegaByte) to bit
	average_image_size = avg_image_size * mb_to_bit		#-- in bits

	downloading_time_per_image = calculate_downloading_time(average_image_size)		#-- in seconds
	total_downloading_time     = downloading_time_per_image * number_of_images		#-- in seconds

	#-- Calculating total downloading time in day, hour, minutes, seconds
	day  = int(total_downloading_time / (24 * 3600))
	time = total_downloading_time     % (24 * 3600)
	hour = int(time / 3600)
	min  = int(time % 3600 / 60)
	sec  = int(time % 60)

	#-- Creating formatted output
	output = "\n"
	output += "+------------------------------------------+\n"
	output += "+--------- TOTAL DOWNLOADING TIME ---------+\n"
	output += "|                                          |\n"
	output += "+--DAYS--+--HOURS--+--MINUTES--+--SECONDS--+\n"
	output += "|   {:02d}       {:02d}         {:02d}          {:02d}     |\n".format(day, hour, min, sec)
	output += "+------------------------------------------+\n"

	print (output)
	logging.info(output)


def get_most_recent_file(files):
	"""
		Returns the file with the most recent modification time from the passed list of files.


		Args:
			files	(list): 	the list of files to be processed for modification time


		Returns:
			string:		the file from the passed list of files with the most recent modification time

	"""
	most_recent_mtime = None
	most_recent_file = ""

	for file in files:
		mtime = os.path.getmtime(file)

		if most_recent_mtime is None or mtime > most_recent_mtime:
			most_recent_mtime = mtime
			most_recent_file  = file

	return most_recent_file


def write_dict_list_to_file(dict_list, out_file):
	"""
		Writes the passed list of dictionaries to the passed file in a valid Json array.
		Note that the readability of the output file is not human friendly for optimization reasons.


		Args:
			dict_list 	(list):		the list of dictionaries to be written to disk
			out_file	(string): 	the absolute path to the output file


		Returns:
			bool: 	True if successful, False otherwise

	"""
	try:
		with open(out_file, "r") as json_file:
			data = json_file.readline()

			if data == "[]":
				#-- The element is the very first one to be written to file
				data      = data.replace("]", json.dumps(dict_list[0]) + "]")
				dict_list = dict_list[1:]

			for dict in dict_list:
				data = data.replace("}]", "}, " + json.dumps(dict) + "]")

		with open(out_file, "w") as json_file:
			json_file.write(data)

	except:
		logging.exception("Failed to write dictionary list to Json file")
		return False

	return True


def write_dict_element_to_file(dict_element, out_file,):
	"""
		Writes the passed dictionary element to the passed file.
		Note that the readability of the output file is not human friendly for optimization reasons.


		Args:
			dict_element	(dict):		a dictionary with a single key (i.e. containing a single dictionary element)
			out_file		(string): 	the absolute path to the output file


		Returns:
			bool: 	True if successful, False otherwise

	"""
	dict_element = dict_element.popitem()
	key          = dict_element[0]
	value        = dict_element[1]

	try:
		with open(out_file, "r") as json_file:
			data = json_file.readline()

			if not data == "{}":
				#-- The element is not the very first to be written to file
				data = data.replace("]}", '], "' + key + '": ' + str(value).replace("'", '"') + "}")
			else:
				data = data.replace("}", '"' + key + '": ' + str(value).replace("'", '"') + "}")

		with open(out_file, "w") as json_file:
			json_file.write(data)

	except:
		logging.exception("Failed to write dictionary element to Json file")
		return False

	return True