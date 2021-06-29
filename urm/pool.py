#!/usr/bin/env python3
# pool.py -*-python-*-

# We use multiprocessing.Queue, so importing queue only for queue.Empty
import concurrent.futures
import multiprocessing
import queue
import sys
import time
import traceback
import yaml

import urm.parser
import urm.ssh

# pylint: disable=unused-import
from urm.log import DEBUG, INFO, ERROR, FATAL, TRACEBACK


class Pool():
    '''Pool will execute jobs in parallel.

    The job may be a simple command that is passed to ssh.

    The job may also be a list of mixed ssh and python commands. Commands in
    this list are assumed to be Python, unless one of the following patterns
    are detected:

    !command                       Will execute a shell command via ssh. Will
                                   run as root if '!!' is used. Output will be
                                   sent to the queue. An error will terminate
                                   execution of the command list.

    var = !command                 Will execute a shell command via ssh and
                                   will store the output in 'var' as a list of
                                   lines. Will run as root if '!!' is used. An
                                   error will terminate execution of the
                                   command list.

    ovar, evar = !command          Will execute a shell command via ssh and
                                   will store the stdout output in 'ovar' and
                                   the stderr output in 'evar', both as a list
                                   of lines. Will run as root if '!!' is used.
                                   Command list execution will continue even
                                   if there is an error.

    :var                           Will send 'var' to the queue.

    %timeout secs                  Will set the timeout to 'secs' (default 5).
                                   A value of 0 will set an unlimited timeout.

    If the shell 'command' is followed by '< var' then the contents of 'var'
    will be send over the ssh channel as stdin to the command.

    All Python code will be executed locally in the thread that is servicing
    this current target. Only the shell commands will be executed remotely on
    the target.

    The 'queue' is a communications channel from the local thread servicing a
    specific target to the master execution thread, which logs all messages
    added to the queue. A queue entry will be a tuple of the form:

        (worker_index, message_type, debug_info, message)

    where the message_type is from the following list:

        message_type        message
        MT_COMMAND          Command that is to be run
        MT_STDOUT           Text from stdout
        MT_STDERR           Text from stderr
        MT_STATUS           Execution status from command
        MT_DEBUG            Debug-level message
        MT_INFO             Info-level message
        MT_ERROR            Error-level message
        MT_FATAL            Fatal-level message

'''
    TIMEOUT = 5
    TIMEOUT_KEYS = ['timeout']
    SSH_PORT = 22
    SSH_PORT_KEYS = ['ssh-port', 'port']
    USERNAME_KEYS = ['username']
    PASSWORD_KEYS = ['password', 'initialpassword']
    APT_KEYS = ['apt']
    NETWORKS_KEYS = ['networks']
    PASSWORDS_KEYS = ['passwords']
    KEYS_KEYS = ['keys']
    NTP_KEYS = ['ntps']
    IP_KEYS = ['ip']

    # Message types
    MT_COMMAND = 0
    MT_STDOUT = 1
    MT_STDERR = 2
    MT_STATUS = 3
    MT_RESULT = 4
    MT_EXCEPTION = 5
    MT_DEBUG = 6
    MT_INFO = 7
    MT_ERROR = 8
    MT_FATAL = 9
    MT_MAX_MESSAGE_TYPE = 9

    def __init__(self, config, target_list, max_workers=4, dry_run=False,
                 debug=False, ip=None):
        self.config = config
        self.target_list = config.expand_target_list(target_list)
        self.max_workers = max_workers
        self.jobs = []
        self.target_config = dict()
        self.dry_run = dry_run
        self.debug = debug
        self.ip = ip

        for target in self.target_list:
            if target not in self.target_config:
                self.target_config[target] = self._config_dict(target)

    @staticmethod
    def _worker(target, unique_target, config_dict, mqueue,
                original_command, transformed_command):
        # pylint: disable=redefined-builtin,exec-used
        assert isinstance(transformed_command, str)

        # This routine is executed in a new pid, so changing global variables
        # here is safe.
        sys.argv = original_command.split()
        __name__ = '__main__'
        try:
            code = compile(transformed_command, filename='<string>',
                           mode='exec')
            # TODO restrict number of local/global variables passed
            exec(code, globals(), locals())
        except Exception as exception:
            raise Exception("".join(traceback.format_exception(
                *sys.exc_info())))

    def _config_dict(self, target):
        port = self.config.get_value_with_default(target, Pool.SSH_PORT_KEYS,
                                                  Pool.SSH_PORT, int)
        username = self.config.get_value_with_default(target,
                                                      Pool.USERNAME_KEYS,
                                                      None, str)
        password = self.config.get_value_with_default(target,
                                                      Pool.PASSWORD_KEYS,
                                                      None, str)
        timeout = self.config.get_value_with_default(target, Pool.TIMEOUT_KEYS,
                                                     Pool.TIMEOUT, int)
        apt = self.config.get_value_with_default(target, Pool.APT_KEYS,
                                                 None, str)

        networks = self.config.get_value_with_default(target,
                                                      Pool.NETWORKS_KEYS,
                                                      None, str)
        if networks is not None and networks[0] == '[':
            networks = yaml.load(networks, Loader=yaml.BaseLoader)

        passwords = self.config.get_value_with_default(target,
                                                       Pool.PASSWORDS_KEYS,
                                                       None, str)
        if passwords is not None and passwords[0] == '[':
            passwords = yaml.load(passwords, Loader=yaml.BaseLoader)

        keys = self.config.get_value_with_default(target,
                                                  Pool.KEYS_KEYS,
                                                  None, str)
        if keys is not None and keys[0] == '[':
            keys = yaml.load(keys, Loader=yaml.BaseLoader)

        ntps = self.config.get_value_with_default(target, Pool.NTP_KEYS,
                                                  None, str)
        if ntps is not None and ntps[0] == '[':
            ntps = yaml.load(ntps, Loader=yaml.BaseLoader)

        if self.ip is not None:
            # Allow a --ip argument to override the .urm configuration file.
            ip = self.ip
        else:
            ip = self.config.get_value_with_default(target, Pool.IP_KEYS,
                                                    None, str)

        return {'target': target,
                'port': port,
                'username': username,
                'password': password,
                'timeout': timeout,
                'apt': apt,
                'networks': networks,
                'passwords': passwords,
                'keys': keys,
                'ntps': ntps,
                'target_ip': ip if ip is not None else target}

    @staticmethod
    def _done_callback(target, future, callback):
        exc = future.exception()
        if exc is not None:
            callback(target, Pool.MT_EXCEPTION, None,
                     'future.exception={}'.format(str(exc)))
            return
        result = future.result()
        if result is not None:
            callback(target, Pool.MT_RESULT, None,
                     'future.result={}'.format(str(future.result())))

    @staticmethod
    def _log_callback(target, msg_type, debug_info, msg):
        code = 'C>!SRXDIEF'[msg_type] \
            if msg_type <= Pool.MT_MAX_MESSAGE_TYPE else '?'
        if debug_info and len(debug_info) > 0:
            INFO(":%c:%s: %s %s", code, target, debug_info, msg)
        else:
            INFO(":%c:%s: %s", code, target, msg)

    def run(self, command, callback=_log_callback.__func__):
        '''Run a command.
        '''

        INFO('command=%s', command)
        parser = urm.parser.Parser(self.config, command, debug=self.debug)
        INFO('parser.command()=\n%s',
             '\n'.join(['{:4d} {}'.format(i, l)
                        for i, l in enumerate(parser.command().split('\n'),
                                              start=1)]))
        if self.dry_run:
            return

        jobs = dict()
        manager = multiprocessing.Manager()
        mqueue = manager.Queue()
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=self.max_workers) as executor:
            for _, target in enumerate(self.target_list):
                # Create a unique target name for messages.
                target_index = 1
                unique_target = target
                while unique_target in jobs:
                    unique_target = target + '(' + str(target_index) + ')'
                    target_index += 1

                # Start the future.
                future = executor.submit(
                    self._worker,
                    target,
                    unique_target,
                    self.target_config[target],
                    mqueue,
                    command,
                    parser.command())
                jobs[unique_target] = future

                # Add in a final callback to capture any errors from the
                # command stream.
                future.add_done_callback(
                    lambda future, target=unique_target, callback=callback:
                    self._done_callback(target, future, callback))

            # While at least one job is running, get results from queue
            running = True
            while running:
                try:
                    target, msg_type, debug_info, msg = mqueue.get(False)
                    callback(target, msg_type, debug_info, msg)
                except queue.Empty:
                    running = False
                    for target, future in jobs.items():
                        running |= future.running()
                    time.sleep(.1)
            while not mqueue.empty():
                target, msg_type, debug_info, msg = mqueue.get(False)
                callback(target, msg_type, debug_info, msg)
