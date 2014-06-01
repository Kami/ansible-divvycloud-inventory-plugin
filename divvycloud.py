#!/usr/bin/env python

"""
DivvyCloud.com Ansible Inventory plugin
=======================================

Generates inventory that Ansible can understand by talking to the DivvyCloud
API v2.0.

When run against a specific host (--host option), this script returns the
following variables:

 - divvy_id
 - divvy_name
 - divvy_cloud
 - divvy_platform
 - divvy_state
 - divvy_public_ip
 - divvy_private_ip
 - divvy_tags_tags
 - ansible_ssh_host

When run in --list mode, instances are grouped into the following categories:

 - status - Instance status (running, stopped, etc.)
 - tags - Instance tags
 - provider - Instance provider (RAX, AWS, etc.)
 - region - Instance region
 - platform - Instance platform (Linux, Windowws, etc.)

Examples:

  Execute uname on all instances running in the Rackspace.

  $ ansible -i divvycloud.py RAX -m shell -a "/bin/uname -a"

  Use the inventory script to print information for a specific instance:

  $ plugins/inventory/divvycloud.py --host 127.0.0.1

Author: Tomaz Muraus <tomaz@divvycloud.com>
Version: 0.0.1
"""

import re
import os
import sys
import httplib
import argparse
import ConfigParser

from collections import defaultdict

try:
    import json
except ImportError:
    import simplejson as json

import requests

DIRNAME = os.path.dirname(os.path.realpath(__file__))

LIST_INSTANCES_PATH = \
    '/v2/resourcegroup/resourcegroup:type_instance:/resources/list'
DEFAULT_CONFIG_PATH = os.path.join(DIRNAME, 'divvycloud.ini')

REQUIRED_CONFIG_ITEMS = {
    'divvycloud': [
        'installation_url',
        'api_key',
        'api_secret'
    ]
}

GROUP_PRFIXES = {
    'provider': 'provider_',
    'region': 'region_',
    'status': 'status_',
    'platform': 'platform_',
    'tag': 'tag_',
    'resource_group': 'resource_group_'
}


class DivvyCloudInventoryPlugin(object):
    def __init__(self):
        # Maps group_name -> instance_ids
        self._groups = defaultdict(list)

        # Stored parsed settings.
        self._settings = {}

    def run(self):
        self._read_settings()
        self._populate_cache()
        self._parse_cli_args()

    def _handle_action(self, action, action_kwargs=None):
        if action == 'list_instances':
            data = self._json_format_dict(self._groups)
        elif action == 'get_instance':
            host = action_kwargs['host']
            data = self.get_instance_information(hostname=host)
            data = self._json_format_dict(data)
        else:
            raise ValueError('Unsupported action: %s' % (action))

        print(data)

    def get_instance_information(self, hostname):
        """
        Retrieve information about an instance based on the instance hostname.
        """
        # TODO: That's not really efficient
        instances = self._retrieve_instances()

        try:
            instance = [i for i in instances if
                        i['public_address'] == hostname][0]
        except IndexError:
            return None

        result = {}
        result['divvy_id'] = instance['id']
        result['divvy_name'] = instance['name']
        result['divvy_cloud'] = instance.get('cloud', None)
        result['divvy_platform'] = instance.get('platform', None)
        result['divvy_state'] = instance.get('state', None)
        result['divvy_public_ip'] = instance.get('public_address', None)
        result['divvy_private_ip'] = instance.get('private_address', None)
        result['divvy_tags'] = instance.get('tags', None)

        # TODO: Use preferred address
        result['ansible_ssh_host'] = instance.get('public_address', None)

        return result

    def _add_instance_to_inventory(self, instance):
        """
        Add instance to inventory and cache.

        :param instance: Dictionary with instance attributes.
        :type instance: ``dict``
        """
        name = instance['name']
        provider = instance.get('cloud', None)
        region = instance.get('region', None)
        platform = instance.get('platform', None)
        status = instance.get('state', 'unknown')
        public_ip = instance.get('public_address', None)
        tags = instance.get('tags', {})

        inventory_key = name

        # Only want running nodes
        if status != 'running':
            return None

        # Ignore nodes without a public IP
        if not public_ip:
            return None

        # Group by status
        if status:
            key = GROUP_PRFIXES['status'] + status
            key = self._escape_group_key(key)
            self._groups[key].append(inventory_key)

        # Group by region
        if region:
            key = GROUP_PRFIXES['region'] + region
            key = self._escape_group_key(key)
            self._groups[key].append(inventory_key)

        # Group by provider
        if provider:
            key = GROUP_PRFIXES['provider'] + provider
            key = self._escape_group_key(key)
            self._groups[key].append(inventory_key)

        # Group by platform
        if platform:
            key = GROUP_PRFIXES['platform'] + platform
            key = self._escape_group_key(key)
            self._groups[key].append(inventory_key)

        # Group by tags
        for tag_name in tags.keys():
            key = GROUP_PRFIXES['tag'] + tag_name
            key = self._escape_group_key(key)
            self._groups[key].append(inventory_key)

    def _populate_cache(self):
        instances = self._retrieve_instances()

        for instance in instances:
            self._add_instance_to_inventory(instance=instance)

    def _retrieve_instances(self):
        """
        Hit the API and retrieve the list of the available instances.
        """
        url = self._settings['installation_url']

        if url.endswith('/'):
            url = url[:-1]

        url += LIST_INSTANCES_PATH
        headers = self._get_base_headers()
        response = requests.post(url, headers=headers)
        data = response.json()

        if response.status_code != httplib.OK:
            print('Failed to retrieve instances list')
            print(response.status_code)
            print(response.text)
            sys.exit(1)

        instances = data['resources']
        return instances

    def _json_format_dict(self, data, pretty=True):
        """
        Converts a dict to a JSON object and dumps it as a formatted string.
        """
        if pretty:
            return json.dumps(data, sort_keys=True, indent=2)
        else:
            return json.dumps(data)

    def _escape_group_key(self, key):
        return re.sub('[^A-Za-z0-9\-]', '_', key)

    def _read_settings(self):
        config_path = os.environ.get('DIVVYCLOUD_INI_PATH',
                                     DEFAULT_CONFIG_PATH)

        config = ConfigParser.SafeConfigParser()
        config.read(config_path)

        for section_name, option_names in REQUIRED_CONFIG_ITEMS.items():
            if not config.has_section(section_name):
                message = 'Config is missing [%s] section"' % (section_name)
                raise ValueError(message)

            for option_name in option_names:
                if (not config.has_option(section_name, option_name) or
                        not config.get(section_name, option_name)):
                    message = ('Missing required %s option in [%s] section' %
                               (section_name, option_name))
                    raise ValueError(message)

                self._settings[option_name] = config.get(section_name,
                                                         option_name)

    def _parse_cli_args(self):
        parser = argparse.ArgumentParser(
            description=('Produce an Ansible Inventory output for DivvyCloud'
                         ' installation'))

        parser.add_argument('--list', action='store_true', default=True,
                            help='List instances (default action)')
        parser.add_argument('--host', action='store',
                            help='Get all information about an instance')
        args = parser.parse_args()

        if args.host:
            self._handle_action(action='get_instance',
                                action_kwargs={'host': args.host})
        else:
            self._handle_action(action='list_instances')

    def _get_base_headers(self):
        headers = {}
        # TODO: Retrieve auth token
        headers['X-API-Key'] = self._settings['api_key']
        headers['X-API-Secret'] = self._settings['api_secret']

        return headers

if __name__ == '__main__':
    DivvyCloudInventoryPlugin().run()
