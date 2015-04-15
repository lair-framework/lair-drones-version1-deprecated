#!/usr/bin/env python

import os
import copy
import re
from urlparse import urlparse
from lairdrone import drone_models as models
from lairdrone import helper

TOOL = 'dirb'

def build_clean_path(base_url, path, replace_specials=False):
	"""Remove the base url value out of a path and optionally replace
	   any special characters with an underscore character (required to 
	   build 'path_clean').

	   :param base_url: Base URL
	   :param path: URI following base URL
	   :param replace_specials: Optional parameter, replaces any special chars with underscore
	"""
	path = path.replace(base_url, '')
	return re.sub('[^a-zA-Z0-9]', '_', path) if replace_specials else path

def extrapolate_args(contents):
	"""Well... since the result output for dirb doesn't give the commands used, I'm gonna have to 
	   do it the hard way! Works backwards from the result output to derive the command line args
	   used. Heavily dependent on the version in use. If any of these expected values change, the
	   regex patterns need to also be updated. Not the best, but what are ya gonna do?

	   :param contents: String value of output file
	"""
	user_agent_pattern = re.compile('USER_AGENT: (.+)')
	cookie_pattern = re.compile('COOKIE: (.+)')
	fine_tuning_pattern = re.compile('OPTION: Fine tunning of NOT_FOUND detection')
	headers_pattern = re.compile('ADDED_HEADERS:.+\n--\n(.+)\n--')
	case_sensitivity_pattern = re.compile('OPTION: Using Case-Insensitive Searches')
	location_pattern = re.compile('OPTION: Printing LOCATION header')
	not_found_pattern = re.compile('OPTION: Ignoring NOT_FOUND code -> (\d+)')
	output_file_pattern = re.compile('OUTPUT_FILE: (.+)')
	proxy_pattern = re.compile('PROXY: (.+)')
	proxy_auth_pattern = re.compile('PROXY AUTHORIZATION: (.+)')
	not_recursive_pattern = re.compile('OPTION: Not Recursive')
	silent_mode_pattern = re.compile('OPTION: Silent Mode')
	trailing_slash_pattern = re.compile('OPTION: NOT forcing an ending')
	http_auth_pattern = re.compile('AUTHORIZATION: (.+)')
	non_existing_pattern = re.compile('OPTION: Show Not Existant Pages')
	stop_warning_pattern = re.compile('OPTION: Not Stoping on warning message')
	extension_list_pattern = re.compile('EXTENSIONS_LIST: \((.+)\) \|')
	extension_file_pattern = re.compile('EXTENSIONS_FILE: (.+)')
	speed_delay_pattern = re.compile('SPEED_DELAY: (\d+) miliseconds')
	
	command_args = []
	command_args.append('-a %s' % user_agent_pattern.findall(contents)[0] if len(user_agent_pattern.findall(contents)) else None)
	command_args.append('-c "%s"' % cookie_pattern.findall(contents)[0] if len(cookie_pattern.findall(contents)) else None)
	command_args.append('-f' if len(fine_tuning_pattern.findall(contents)) else None)
	command_args.append('-H "%s"' % headers_pattern.findall(contents)[0] if len(headers_pattern.findall(contents)) else None)
	command_args.append('-i' if len(case_sensitivity_pattern.findall(contents)) else None)
	command_args.append('-l' if len(location_pattern.findall(contents)) else None)
	command_args.append('-N %s' % not_found_pattern.findall(contents)[0] if len(not_found_pattern.findall(contents)) else None)
	command_args.append('-o %s' % output_file_pattern.findall(contents)[0] if len(output_file_pattern.findall(contents)) else None)
	command_args.append('-p %s' % proxy_pattern.findall(contents)[0] if len(proxy_pattern.findall(contents)) else None)
	command_args.append('-P %s' % proxy_auth_pattern.findall(contents)[0] if len(proxy_auth_pattern.findall(contents)) else None)
	command_args.append('-r' if len(not_recursive_pattern.findall(contents)) else None)
	command_args.append('-S' if len(silent_mode_pattern.findall(contents)) else None)
	command_args.append('-t' if len(trailing_slash_pattern.findall(contents)) else None)
	command_args.append('-u %s' % http_auth_pattern.findall(contents)[0] if len(http_auth_pattern.findall(contents)) else None)
	command_args.append('-v' if len(non_existing_pattern.findall(contents)) else None)
	command_args.append('-w' if len(stop_warning_pattern.findall(contents)) else None)
	command_args.append('-X %s' % extension_list_pattern.findall(contents)[0] if len(extension_list_pattern.findall(contents)) else None)
	command_args.append('-x %s' % extension_file_pattern.findall(contents)[0] if len(extension_file_pattern.findall(contents)) else None)
	command_args.append('-z %s' % speed_delay_pattern.findall(contents)[0] if len(speed_delay_pattern.findall(contents)) else None)

	return 'dirb %s' % ' '.join(filter(None, command_args))

def extract_data(contents):
	"""Take the output file contents and parse out the results as well as the commands used.

	:param contents: String value of dirb output file
	"""
	base_url_pattern = re.compile('URL_BASE: (.+)(\/)?\n')
	directory_pattern = re.compile('DIRECTORY: (.+)')
	file_pattern = re.compile('\+ (.+) \(CODE:(\d{3})')

	arguments = extrapolate_args(contents)

	try:
		base_url = base_url_pattern.findall(contents)[0]

		# base_url at this point is a tuple, with the 2nd item value 
		# being the 2nd matched group, so we can disregard that.
		base_url = base_url[0] if not base_url[0].endswith('/') else base_url[0][:-1]
		parsed_url = urlparse(base_url)
		port = parsed_url.port if parsed_url.port else 80
	except Exception as exception:
		print exception

	directories = [(x, '200') for x in directory_pattern.findall(contents)]
	files = file_pattern.findall(contents)
	results = directories + files
	final_results = []
	for record in results:
		final_results.append({
			'path': build_clean_path(base_url, record[0]),
			'path_clean': build_clean_path(base_url, record[0], True),
			'port': port,
			'response_code': record[1],
			'flag': False,
		})
	return parsed_url.hostname, arguments, final_results

def parse(project, resource):
	"""Parses a Dirb file and updates the Lair database

	:param project: The project id
	:param resource: The output file provided by dirb
	"""

	# Attempt to parse resource as a file or string
	try:
		if os.path.isfile(resource):
			with open(resource, 'r') as fh:
				contents = fh.read()
		else:
			contents = resource
	except Exception as exception:
		print exception

	host_ip, arguments, extracted_data = extract_data(contents)

	# Create the project dictionary which acts as foundation of document
	project_dict = copy.deepcopy(models.project_model)
	project_dict['project_id'] = project

	# Pull the command from the file
	command_dict = copy.deepcopy(models.command_model)
	command_dict['tool'] = TOOL
	command_dict['command'] = arguments

	project_dict['commands'].append(command_dict)

	# Proecess host data
	host_dict = copy.deepcopy(models.host_model)
	host_dict['string_addr'] = host_ip
	host_dict['web_directories'] = extracted_data

	project_dict['hosts'].append(host_dict)
	return project_dict
