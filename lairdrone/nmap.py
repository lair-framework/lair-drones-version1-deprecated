#!/usr/bin/env python
# Copyright (c) 2013 Tom Steele, Dan Kottmann, FishNet Security
# See the file license.txt for copying permission

import os
import copy
import re
import xml.etree.ElementTree as et
from lairdrone import drone_models as models
from lairdrone import helper

OS_WEIGHT = 50
TOOL = "nmap"

def parse_grep(project, resource):
    """Parses an Nmap Grepable file and updates the Lair database

    :param project: The project id
    :param resource: The Nmap grepable file or string to be parsed
    """
    command_pattern = re.compile('as: (.+)\n')
    host_status_pattern = re.compile('Host: ([0-9.]*)\s(.+)\sStatus: (\w+)')
    host_service_line = re.compile('Host: ([0-9.]*).*?Ports:(.*)')
    host_service_pattern = re.compile('\s(\d+)\/([^/]+)?\/([^/]+)?\/([^/]+)?\/([^/]+)?\/([^/]+)?\/([^/]+)?\/')
    contents = ''

    try:
        if os.path.isfile(resource):
            with open(resource, 'r') as fh:
                contents = fh.read()
        else:
            pass
    except Exception as exception:
        print exception

    # Create the project dictionary which acts as foundation of document
    project_dict = copy.deepcopy(models.project_model)
    project_dict['project_id'] = project

    # Pull the command from the file
    command_dict = copy.deepcopy(models.command_model)
    command_dict['tool'] = TOOL

    command_results = command_pattern.findall(contents)
    command_dict['command'] = command_results[0] if len(command_results) else ''

    project_dict['commands'].append(command_dict)

    # Process each 'host' in the file
    for host_match in host_status_pattern.findall(contents):
        host_ip, host_name, status = host_match
        
        host_dict = copy.deepcopy(models.host_model)

        # Parse the host status
        if status != 'Up':
            host_dict['alive'] = False

        if not host_dict.get('alive',False):
            # Don't import dead hosts
            continue

        # Parse the host IP
        host_dict['string_addr'] = host_ip

        # Parse the host name
        host_dict['hostnames'].append(host_name.strip('() '))

        # Find the ports
        for service_line_match in host_service_line.findall(contents):
            ip, service_details = service_line_match
            for port_match in host_service_pattern.findall(service_details):
                port, state, protocol, owner, service, rpc_info, version = port_match
                port_dict = copy.deepcopy(models.port_model)
                if host_ip == ip:
                    port_dict['port'] = int(port)
                    port_dict['protocol'] = protocol

                    # Parse port status
                    if state != 'open':
                        continue
                    port_dict['alive'] = True

                    # Parse port service and product
                    port_dict['service'] = service
                    port_dict['product'] = version

                    host_dict['ports'].append(port_dict)

        # Find the Operating System
        # TODO: grep output may not be sufficient.
        # os_dict = copy.deepcopy(models.os_model)
        # os_dict['tool'] = TOOL

        # host_dict['os'].append(os_dict)

        project_dict['hosts'].append(host_dict)
    return project_dict


def parse_xml(project, resource):
    """Parses an Nmap XML file and updates the Lair database

    :param project: The project id
    :param resource: The Nmap xml file or xml string to be parsed
    """

    # Attempt to parse resource as file or string
    try:
        if os.path.isfile(resource):
            tree = et.parse(resource)
            root = tree.getroot()
        else:
            root = et.fromstring(resource)
    except et.ParseError:
        raise

    # Create the project dictionary which acts as foundation of document
    project_dict = copy.deepcopy(models.project_model)
    project_dict['project_id'] = project

    # Pull the command from the file
    command_dict = copy.deepcopy(models.command_model)
    command_dict['tool'] = TOOL

    if root.tag == 'nmaprun':
        command_dict['command'] = root.attrib['args']
    else:
        command = root.find('nmaprun')
        if command is not None:
            command_dict['command'] = command.attrib['args']

    project_dict['commands'].append(command_dict)

    # Process each 'host' in the file
    for host in root.findall('host'):

        host_dict = copy.deepcopy(models.host_model)

        # Find the host status
        status = host.find('status')
        if status is not None:
            if status.attrib['state'] != 'up':
                host_dict['alive'] = False

        if status is None or not host_dict.get('alive', False):
            # Don't import dead hosts
            continue

        # Find the IP address and/or MAC address
        for addr in host.findall('address'):

            # Get IP address
            if addr.attrib['addrtype'] == 'ipv4':
                host_dict['string_addr'] = addr.attrib['addr']
                host_dict['long_addr'] = helper.ip2long(addr.attrib['addr'])
            elif addr.attrib['addrtype'] == 'mac':
                host_dict['mac_addr'] = addr.attrib['addr']

        # Find the host names
        for hostname in host.iter('hostname'):
            host_dict['hostnames'].append(hostname.attrib['name'])

        # Find the ports
        for port in host.iter('port'):
            port_dict = copy.deepcopy(models.port_model)
            port_dict['port'] = int(port.attrib['portid'])
            port_dict['protocol'] = port.attrib['protocol']

            # Find port status
            status = port.find('state')
            if status is not None:
                if status.attrib['state'] != 'open':
                    continue
                port_dict['alive'] = True

            # Find port service and product
            service = port.find('service')
            if service is not None:
                port_dict['service'] = service.attrib['name']
                if 'product' in service.attrib:
                    if 'version' in service.attrib:
                        port_dict['product'] = service.attrib['product'] + " " + service.attrib['version']
                    else:
                        port_dict['product'] = service.attrib['product']
                else:
                    port_dict['product'] = "unknown"

            # Find NSE script output
            for script in port.findall('script'):
                note_dict = copy.deepcopy(models.note_model)
                note_dict['title'] = script.attrib['id']
                note_dict['content'] = script.attrib['output']
                note_dict['last_modified_by'] = TOOL
                port_dict['notes'].append(note_dict)

            host_dict['ports'].append(port_dict)

        # Find the Operating System
        os_dict = copy.deepcopy(models.os_model)
        os_dict['tool'] = TOOL
        os_list = list(host.iter('osmatch'))
        if os_list:
            os_dict['weight'] = OS_WEIGHT
            os_dict['fingerprint'] = os_list[0].attrib['name']

        host_dict['os'].append(os_dict)

        project_dict['hosts'].append(host_dict)

    return project_dict