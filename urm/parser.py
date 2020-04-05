#!/usr/bin/env python3
# parser.py -*-python-*-

import os
import re

# pylint: disable=unused-import
from urm.log import DEBUG, INFO, ERROR, FATAL, TRACEBACK


class Parser():
    def __init__(self, config, command, debug=False):
        self.config = config
        self.input_command = command
        self.debug = debug

        self.params = command.split()
        INFO('PARAMS=%s', self.params)
        self.prefix = self.params[0]
        INFO('PREFIX=%s', self.prefix)
        self.output_command = ''
        if self.input_command[0] == '.':
            self._complex()
        else:
            self._oneline()

    @staticmethod
    def _stringify(original_string):
        return "'" + original_string.translate(str.maketrans({
            "\\": r"\\",
            "'": r"\'",
            '"': r'\"'
        })) + "'"

    def _wrap_text(self, input_text):
        output_text = '''\
_ssh_ = urm.ssh.Ssh(target, unique_target, config_dict, queue, debug=%s)

''' % self.debug
        eof_line = None
        lines = ''
        insert_global = False
        INFO("input_text='%s'", input_text)
        for line in input_text.splitlines():
            lline = line.lstrip()
            if insert_global:
                output_text += ' ' * (len(line) - len(lline)) + \
                    'global _ssh_\n'
                insert_global = False

            if eof_line is None:
                # Transform print( -> _ssh_.INFO(
                line = re.sub(r'([^a-z])print\(', r'\1_ssh_.INFO(', line)

                # Determine the method to use for ! and !!
                if re.search(r'^!!(.*)', lline) or re.search(r'= ?!!(.*)',
                                                             line):
                    method = 'su'
                elif re.search(r'^!(.*)', lline) or re.search(r'= ?!(.*)',
                                                              line):
                    method = 'run'
                else:
                    method = None

            if line.strip().endswith('<<EOF'):
                eof_line = line[:-6].rstrip()
                continue
            if eof_line is not None and not line.strip().startswith('EOF'):
                lines += line + '\n'
                continue

            # Transform !, !!, and :
            if method is not None:
                if eof_line is not None:
                    INFO("lines='%s'" % lines)
                    line = re.sub(r'!?!(.*)',
                                  '_ssh_.' + method +
                                  "('''\\1''', input='''" + lines + "''')",
                                  eof_line)
                    lines = ''
                else:
                    line = re.sub(r'!?!(.*)',
                                  '_ssh_.' + method + "('''\\1''')", line)

            eof_line = None
            output_text += line + '\n'
            if re.search(r'\s*def\s', line):
                insert_global = True
        return output_text

    def _wrap_file(self, filename):
        with open(filename, 'r') as fp:
            content = fp.read()
        output_text = '# Command from CLI: {}\n'.format(self.input_command)
        output_text += self._wrap_text(content)
        return output_text

    def _oneline(self):
        assert self.input_command[0] != '.'
        if self.input_command[0] == '!':
            self.output_command = self._wrap_text(self.input_command)
        else:
            self.output_command = self._wrap_text('!' + self.input_command)

    def _complex(self):
        assert self.input_command[0] == '.'
        if os.path.exists(self.prefix):
            self.output_command = self._wrap_file(self.prefix)
        else:
            FATAL('Cannot find file: %s', self.prefix)

    def command(self):
        return self.output_command
