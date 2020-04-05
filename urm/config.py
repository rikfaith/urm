#!/usr/bin/env python3
# config.py -*-python-*-

import configparser
import os

# pylint: disable=unused-import
from urm.log import PDLOG_SET_LEVEL, DEBUG, INFO, ERROR, FATAL, DECODE


class Config():
    '''Parse a set of config files and return values for keys.

    Sections names are either:
    * machine names (short name, ip addresses, fqdn, etc.), or
    * set names

    If a section called [default] is present, then default values will be taken
    from that section. If a machine is part of a set, then the set section may
    also have default values.

    If multiple sections, perhaps in multiple files, have values for the same
    key, all values will be returned.

    If multiple config files have set entries with possibly disjoint lists of
    hosts, then the union will be returned.
'''

    DEFAULT_SECTIONS = ["DEFAULT", "default"]

    def __init__(self, paths=None,
                 username=None,
                 password=None):
        if paths is None:
            self.paths = ["~/.urm",
                          "~/.config/urm/config",
                          "/etc/urm/config"]
        else:
            if isinstance(paths, list):
                self.paths = paths
            else:
                self.paths = [paths]
        self.username = username
        self.password = password
        self.configs = []
        self._parse_configs()

    def _parse_configs(self):
        INFO('self.paths=%s', self.paths)
        for path in self.paths:
            filename = os.path.expanduser(path)
            if os.path.exists(filename):
                config = configparser.ConfigParser(allow_no_value=True)
                config.read(filename)
                self.configs.append(config)

    def _find_sections_containing(self, target):
        sections = []
        for config in self.configs:
            for section in config:
                if target in config[section] and \
                   config[section].get(target) is None:
                    sections.append(section)
        return sections

    def _get_value(self, target, key):
        values_seen = set()
        values = []
        for config in self.configs:
            if target in config:
                value = config[target].get(key)
                if value is not None and value not in values_seen:
                    values.append(value)
                    values_seen.add(value)
        if values:
            return values
        return None

    def get_value(self, target, key):
        if self.username and key == 'username':
            return [self.username]
        if self.password and key == 'password':
            return [self.password]

        # First, return the values in the section called [host]
        value = self._get_value(target, key)
        if value:
            return value

        # Next, return default values from the sections that contain 'host'
        default_values = []
        for section in self._find_sections_containing(target):
            value = self._get_value(section, key)
            if value:
                default_values += value
        if default_values:
            return default_values

        # Last, look for the DEFAULT_SECTIONS
        default_values = []
        for section in Config.DEFAULT_SECTIONS:
            value = self._get_value(section, key)
            if value:
                default_values += value
        return default_values if default_values else None

    def get_value_with_default(self, target, keys, default_value,
                               return_type=str):
        retval = default_value
        for key in keys:
            value = self.get_value(target, key)
            if value:
                retval = value[0]
                break
        if retval is None:
            return None
        return return_type(retval)

    def _find_target_list(self, target):
        hosts = []
        for config in self.configs:
            if target not in config:
                continue
            found_list = False
            for key in config[target]:
                value = config[target].get(key)
                if value is None:
                    hosts.append(key)
                    found_list = True
            if not found_list:
                hosts.append(target)
        if hosts:
            return hosts
        return [target]

    def expand_target_list(self, target_list):
        if isinstance(target_list, list):
            previous_result = target_list
        else:
            previous_result = [target_list]
        while True:
            # Preserve ordering while generating the union of all of the hosts
            # in the list. Note that some entries might still refer to the
            # same host (e.g., if listed by domain name and by IP).
            targets_seen = set()
            result = []
            for target in previous_result:
                if target not in targets_seen:
                    result += self._find_target_list(target)
                    targets_seen.add(target)
            if previous_result == result:
                break
            previous_result = result
        return result

    def dump(self):
        output = ''
        for config in self.configs:
            for section in config:
                output += '\n[' + section + ']\n'
                for key, value in config[section].items():
                    if value is not None:
                        output += key + ' = ' + value + '\n'
                    else:
                        output += key + '\n'
        return output
