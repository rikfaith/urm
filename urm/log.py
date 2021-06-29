#!/usr/bin/env python3
# log.py -*-python-*-

'''
LICENSE
  This is free and unencumbered software released into the public domain.

  Anyone is free to copy, modify, publish, use, compile, sell, or
  distribute this software, either in source code form or as a compiled
  binary, for any purpose, commercial or non-commercial, and by any
  means.

  In jurisdictions that recognize copyright laws, the author or authors
  of this software dedicate any and all copyright interest in the
  software to the public domain. We make this dedication for the benefit
  of the public at large and to the detriment of our heirs and
  successors. We intend this dedication to be an overt act of
  relinquishment in perpetuity of all present and future rights to this
  software under copyright law.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.

  For more information, please refer to <http://unlicense.org/>

USAGE
    from log import DEBUG, INFO, ERROR, FATAL
  or, if setting the level:
    from log import PDLOG_SET_LEVEL, DEBUG, INFO, ERROR, FATAL

  Then, in your code, log a message:
    value = 42
    INFO('This in an informational message, value=%d', value)
'''

import inspect
import logging
import os
import sys
import time
import traceback


class PDLog():
    logger = None
    initial_level_set = False

    class PDLogFormatter(logging.Formatter):
        def __init__(self):
            logging.Formatter.__init__(self)

        def format(self, record):
            level = record.levelname[0]
            date = time.localtime(record.created)
            date_msec = (record.created - int(record.created)) * 1000
            stamp = '%c%04d%02d%02d %02d:%02d:%02d.%03d' % (
                level,
                date.tm_year, date.tm_mon, date.tm_mday,
                date.tm_hour, date.tm_min, date.tm_sec, date_msec)
            caller = inspect.getframeinfo(inspect.stack()[9][0])
            filename = '/'.join(caller.filename.split('/')[-2:])
            lineno = ' %s:%d' % (filename, caller.lineno)
            pid = ' %d' % os.getpid()
            message = '%s%s%s %s' % (stamp, lineno, pid,
                                     PDLog.format_message(record))
            record.getMessage = lambda: message
            return logging.Formatter.format(self, record)

    def __init__(self):
        PDLog.logger = logging.getLogger()
        logging.addLevelName(50, 'FATAL')
        handler = logging.StreamHandler()
        handler.setFormatter(PDLog.PDLogFormatter())
        PDLog.logger.addHandler(handler)
        self.set_level('INFO')

    @staticmethod
    def format_message(record):
        # pylint: disable=broad-except
        try:
            msg = '%s' % (record.msg % record.args)
        except Exception as exception:
            msg = repr(record.msg) + \
                ' EXCEPTION: ' + repr(exception) + \
                ' record.msg=' + repr(record.msg) + \
                ' record.args=' + repr(record.args)
        return msg

    @staticmethod
    def set_level(newlevel):
        old_level = PDLog.logger.getEffectiveLevel()
        if newlevel == 'DEBUG':
            PDLog.logger.setLevel(10)
        elif newlevel == 'INFO':
            PDLog.logger.setLevel(20)
        elif newlevel == 'ERROR':
            PDLog.logger.setLevel(40)
        else:
            PDLog.logger.setLevel(newlevel)
        new_level = PDLog.logger.getEffectiveLevel()

        if PDLog.initial_level_set:
            PDLog.logger.info('Log change: level %s (%s) to level %s (%s)',
                              old_level,
                              logging.getLevelName(old_level),
                              new_level,
                              logging.getLevelName(new_level))
        PDLog.initial_level_set = True

    @staticmethod
    def fatal(message, *args, **kwargs):
        logging.fatal(message, *args, **kwargs)
        sys.exit(1)

    @staticmethod
    def decode(message, *args, **kwargs):
        exc_type, exc_value = sys.exc_info()[:2]
        exc = traceback.format_exception_only(exc_type, exc_value)
        logging.error(message + ': ' + exc[0].strip(), *args, **kwargs)

    @staticmethod
    def get_stack_from_traceback(exc_traceback):
        tback = traceback.extract_tb(exc_traceback, limit=5)
        stack = ''
        for filename, lineno, _, _ in tback:
            if stack != '':
                stack += '; '
            stack += '%s:%s' % (os.path.basename(filename), lineno)
        return stack

    @staticmethod
    def traceback(exc_traceback, message, *args, **kwargs):
        stack = PDLog.get_stack_from_traceback(exc_traceback)
        logging.error(message + ' (%s)' % stack, *args, **kwargs)


# Define global aliases to debugging functions.
DEBUG = logging.debug
INFO = logging.info
ERROR = logging.error
FATAL = PDLog.fatal
DECODE = PDLog.decode
TRACEBACK = PDLog.traceback
PDLOG_SET_LEVEL = PDLog.set_level

# Instantiate the class
PDLog()
