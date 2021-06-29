#!/usr/bin/env python3
# ssh.py -*-python-*-

# Using socket only for socket.timeout
import inspect
import ipaddress
import logging
import os
import re
import select
import socket
import sys
import time

import dns.resolver
import paramiko

import urm.pool
import urm.log


class Ssh():
    '''When the Ssh object is instantiated, it will open a connection to the
    specified remote target.

    Each call to Ssh.run() will execute the specified command on the remote
    target and will return two lists, one containing the lines from stdout and
    the other containing the lines from the stderr.

    '''

    def __init__(self, target, unique_target, config_dict, queue, debug=False):
        self.target = target
        self.unique_target = unique_target
        self.config_dict = config_dict
        self.queue = queue
        self.debug = debug

        self.port = self.config_dict.get('port', 22)
        self.username = self.config_dict.get('username', None)
        self.password = self.config_dict.get('password', None)
        self.initialpassword = self.config_dict.get('initialpassword', None)
        self.timeout = self.config_dict.get('timeout', 5)
        self.INFO('target=%s username=%s', self.target, self.username)

        # True if an ssh connection has been established.
        self.connected = False

        # True if an ssh commend is running (via self.cmd) but self.ret has
        # not been called yet to obtain the results.
        self.running = False

        # Set when we determine how to access root. Valid values are: unknown,
        # su, sudo. If a password is required, the value will be in
        # 'sudo_password'.
        self.sudo = 'unknown'
        self.sudo_password = None

        if self.config_dict['target_ip'] is not None:
            self.INFO('Replacing target=%s with target=%s', self.target,
                      self.config_dict['target_ip'])
            self.target = self.config_dict['target_ip']

        # Check the validity of the target, which must be an IP address or a
        # dns-resolvable hostname.
        self._verify_target()

        # Open the connection
        self._connect()

    def queue_put(self, worker_index, message_type, message, args=None,
                  depth=1):
        if self.debug:
            now = time.time()
            date = time.localtime(now)
            date_msec = (now - int(now)) * 1000
            stamp = '%02d:%02d:%02d.%03d' % (
                date.tm_hour, date.tm_min, date.tm_sec, date_msec)
            caller = inspect.getframeinfo(inspect.stack()[depth][0])
            filename = '/'.join(caller.filename.split('/')[-2:])
            lineno = ' %s:%d' % (filename, caller.lineno)
            pid = ' %d' % os.getpid()
            debug_info = '%s%s%s' % (stamp, lineno, pid)
        else:
            debug_info = None

        msg = str(message)
        if args is None or len(args) == 0:
            self.queue.put((worker_index, message_type, debug_info, msg))
        else:
            self.queue.put((worker_index, message_type, debug_info,
                            msg % args))

    def INFO(self, message, *args):
        # pylint: disable=invalid-name
        if self.queue:
            self.queue_put(self.unique_target, urm.pool.Pool.MT_INFO,
                           message, args, depth=2)
        else:
            urm.log.INFO(message, args)

    def FATAL(self, message, *args):
        # pylint: disable=invalid-name
        if self.queue:
            self.queue_put(self.unique_target, urm.pool.Pool.MT_FATAL,
                           message, args, depth=2)
        else:
            urm.log.FATAL(message, args)
        sys.exit(1)

    def _verify_target(self):
        '''Make sure the target is either an ip address or a valid DNS name.
        Raise informative exceptions if not.'''


        # Is this an IP address?
        is_ip_address = True
        try:
            ipaddress.ip_address(self.target)
        except ValueError:
            is_ip_address = False
        except Exception as exception:
            raise Exception(self.format_exception('cannot interpret %s' %
                                                  self.target,
                                                  str(exception)))

        # Is this a valid DNS name?
        if not is_ip_address:
            # pylint: disable=broad-except
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            try:
                resolver.query(self.target, 'A')
            except dns.resolver.NXDOMAIN as exception:
                self.FATAL('cannot resolve %s: %s', self.target,
                           str(exception))
            except Exception as exception:
                self.FATAL('cannot resolve %s: %s (%s)', self.target,
                           str(exception), type(exception))

    @staticmethod
    def format_exception(prefix, msg):
        _, _, exc_tb = sys.exc_info()
        stack = urm.log.PDLog.get_stack_from_traceback(exc_tb)
        return prefix + ': ' + msg + ' (%s)' % stack

    def _try_connect(self, target, username, port, password=None):
        # pylint: disable=broad-except
        prefix = 'cannot connect to %s:%d as %s' % (target, port, username)
        try:
            self.client.connect(target, username=username, password=password,
                                port=port, timeout=self.timeout)
        except paramiko.ssh_exception.BadAuthenticationType as exception:
            return self.format_exception(prefix,
                                         'bad authentication: %s' %
                                         exception.explanation)
        except paramiko.ssh_exception.AuthenticationException:
            return self.format_exception(prefix, 'authentication failed')
        except paramiko.ssh_exception.BadHostKeyException as exception:
            return self.format_exception(prefix,
                                         'bad host key %s (expected %s)' %
                                         (exception.key.get_base64(),
                                          exception.expected_key.get_base64()))
        except paramiko.ssh_exception.ChannelException as exception:
            return self.format_exception(prefix,
                                         'could not open channel (%d): %s' %
                                         (exception.code, exception.text))
        except Exception as exception:
            prefix += ' (%s)' % type(exception)
            return self.format_exception(prefix, str(exception))
        return None

    def _connect(self):
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        self.client = paramiko.client.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.client.AutoAddPolicy())

        msg = self._try_connect(self.target, self.username, self.port)
        if msg and self.password:
            msg = self._try_connect(self.target, self.username, self.port,
                                    self.password)
        if msg and self.initialpassword:
            msg = self._try_connect(self.target, self.username, self.port,
                                    self.initialpassword)
        if msg:
            raise Exception(msg)
        self.connected = True

    @staticmethod
    def _linesplit(channel, timeout=None, ending=None):
        channel.setblocking(0)
        start = time.time()
        buffer = ''
        while not channel.exit_status_ready():
            rlist, _, _ = select.select([channel], [], [], 1.0)
            if len(rlist) == 0:
                if timeout and time.time() - start > timeout:
                    break
                if ending and buffer.endswith(ending):
                    break
                continue
            if len(rlist) > 0:
                try:
                    buffer += channel.recv(4096).decode('utf-8')
                except socket.timeout:
                    time.sleep(.1)
            while '\n' in buffer or '\r' in buffer:
                try:
                    line, buffer = re.split('[\r\n]+', buffer, 1)
                except ValueError:
                    yield re.sub(r'[\n\r]*', '', buffer)
                    buffer = ''
                    break
                yield line
        try:
            buffer += channel.recv_stderr(4096).decode('utf-8')
        except socket.timeout:
            time.sleep(.1)
        if len(buffer) > 0:
            yield buffer

    def _determine_sudo(self):
        channel = self.client.get_transport().open_session()
        channel.get_pty()
        channel.exec_command('sudo whoami')
        for line in self._linesplit(channel, timeout=self.timeout):
            pass
        # The exist status might be because sudo is asking for a password. In
        # this case, this option isn't working like we think it should,
        # perhaps because sudo was incorrectly installed.
        if channel.exit_status_ready():
            exit_status = channel.recv_exit_status()
            if exit_status == 0:
                self.sudo = 'sudo'
                return

        channel = self.client.get_transport().open_session()
        channel.get_pty()
        channel.exec_command('su -c whoami')
        for line in self._linesplit(channel, timeout=self.timeout,
                                    ending='word: '):
            if line.endswith('word: '):
                channel.send(self.password + '\n')
                self.sudo_password = self.password
        exit_status = channel.recv_exit_status()
        if exit_status == 0:
            self.sudo = 'su'
            return

        self.FATAL("Unable to determine sudo method")

    def su(self, command, input_text=None):
        # pylint: disable=invalid-name
        self.queue_put(self.unique_target, urm.pool.Pool.MT_COMMAND, command)
        return self.run(command, input_text=input_text, sudo=True, depth=2)

    def substitute(self, target, depth, special=False):
        class FormatDict(dict):
            '''str.format will raise KeyError, so we replace the dictionary
            with this class and use format_map instead.'''
            def __missing__(self, key):
                return '{' + key + '}'

        result = None
        frame = inspect.currentframe()
        try:
            variables = FormatDict(frame.f_back.f_globals)
            if depth == 1:
                variables.update(frame.f_back.f_locals)
            elif depth == 2:
                variables.update(frame.f_back.f_back.f_locals)
            elif depth == 3:
                variables.update(frame.f_back.f_back.f_back.f_locals)
            else:
                raise Exception('Unsupported depth={}'.format(depth))

            mapdict = FormatDict({**self.config_dict, **variables})

            result = None
            if special and target[0] == '{' and target[-1] == '}' and \
               len(re.findall(r'{', target)) == 1:
                # Maintain type
                for key, value in mapdict.items():
                    if key == target[1:-1]:
                        result = value
                        break

            if result is None:
                result = target.format_map(mapdict)
        except ValueError as err:
            pos = int(err.args[0].split()[-1])
            start, stop = max(0, pos - 20), max(pos + 20, len(target))
            indent = pos - start
            snippet = target[start:stop]
            if start > 0:
                snippet = '... ' + snippet
                indent += 4
            if stop < len(target):
                snippet += ' ...'
            self.INFO('Could not substitute variable: %s',
                      snippet)
            self.FATAL('Could not substitute variable: %s',
                       ' ' * indent + '^')
        finally:
            del frame
        return result

    def run(self, command, input_text=None, sudo=False, depth=1):
        assert self.connected
        assert not self.running
        if sudo and self.sudo == 'unknown':
            self._determine_sudo()

        command = self.substitute(command, depth + 1)
        if command is None:
            if self.queue is not None:
                self.queue_put(self.unique_target, urm.pool.Pool.MT_STATUS,
                               'no command')
            return []
        if input_text:
            input_text = self.substitute(input_text, depth + 1)
            if input_text is None:
                if self.queue is not None:
                    self.queue_put(self.unique_target, urm.pool.Pool.MT_STATUS,
                                   'no input')
                return []

        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            time.sleep(1)
            self._connect()
            time.sleep(1)
        channel = self.client.get_transport().open_session()

        if sudo:
            if self.sudo == 'su':
                command = 'su -c "PATH=/sbin:/usr/sbin:$PATH {}"'.\
                    format(command.replace('"', r'\"'))
            elif self.sudo == 'sudo':
                command = 'sudo PATH=/sbin:/usr/sbin:$PATH {}'.format(command)
            else:
                self.FATAL('Unsupported sudo method: {}'.format(self.sudo))
            if input_text is not None or self.sudo_password is not None:
                channel.get_pty()

        self.queue_put(self.unique_target, urm.pool.Pool.MT_COMMAND, command)
        channel.exec_command(command)

        if sudo and self.sudo_password is not None:
            for line in self._linesplit(channel, timeout=self.timeout,
                                        ending='word: '):
                if line.endswith('word: '):
                    channel.send(self.password + '\n')
                # if eof:
                #     channel.send(b'\x04')

        lines = []
        if not channel.exit_status_ready():
            if input_text is not None:
                channel.send(input_text)
                channel.send(b'\x04')
            channel.shutdown_write()

            for line in self._linesplit(channel):
                line = line.rstrip('\r\n')
                if len(line) == 0:
                    continue
                lines.append(line)
                if self.queue is not None:
                    self.queue_put(self.unique_target, urm.pool.Pool.MT_STDOUT,
                                   line)

        exit_status = channel.recv_exit_status()
        if self.queue is not None:
            self.queue_put(self.unique_target, urm.pool.Pool.MT_STATUS,
                           exit_status)
        return lines
