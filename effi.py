#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import getpass
import logging
from configparser import ConfigParser
from collections import defaultdict
import functools
import operator
import stat
import sys
import imapclient
import importlib
import imaplib

__version__ = '0.2'


# ==============================================================================
# Command line argument parser
# ==============================================================================
# Create parser
argparser = argparse.ArgumentParser(
    description='Email filter for IMAP',
    epilog='Options given via command line are preferred over options set in'
           ' config file.',
    add_help=False
)
# Add optional arguments
argparser.add_argument(
    '--help',
    action='help',
    help='show this help message and exit'
)
# General settings
group_general = argparser.add_argument_group('general settings')
group_general.add_argument(
    '-f', '--folder',
    help='set the IMAP folder which should be watched'
)
group_general.add_argument(
    '-i', '--ignore',
    default='',
    help='set the IMAP folders which should be ignored'
)
group_general.add_argument(
    '-c', '--config',
    default='~/.config/effi/effi.cfg',
    help='set the config file (default: %(default)s)'
)
group_general.add_argument(
    '-s', '--script',
    default='~/.config/effi/rules.py',
    help='set the script file (default: %(default)s)'
)
# IMAP settings
group_imap = argparser.add_argument_group('IMAP settings')
group_imap.add_argument(
    '-h', '--host',
    help='set the host'
)
group_imap.add_argument(
    '-u', '--user',
    help='set the user'
)
group = group_imap.add_mutually_exclusive_group()
group.add_argument(
    '-p', '--password',
    help='set the password'
)
group.add_argument(
    '-P', '--read-password',
    action='store_true',
    help='read the password from terminal input'
)
# Logging
group_logging = argparser.add_argument_group('logging and output settings')
group_logging.add_argument(
    '-l', '--log-file',
    default='~/.local/share/effi.log',
    help='set the log file (default: %(default)s)'
)
group = group_logging.add_mutually_exclusive_group()
group.add_argument(
    '-v', '--verbose',
    action='store_true',
    default=False,
    help='be verbose'
)
group.add_argument(
    '-q', '--quiet',
    action='store_true',
    default=False,
    help='don\'t output anything'
)
# Version
argparser.add_argument(
    '--version',
    action='version',
    version='%(prog)s ' + __version__,
    help='show version information and exit'
)
# Parse the arguments
args = argparser.parse_args()
# Make Path absolute
args.config = os.path.abspath(os.path.expanduser(args.config)) if args.config \
    else None
args.script = os.path.abspath(os.path.expanduser(args.script)) if args.script \
    else None

# ==============================================================================
# Logging
# ==============================================================================
log_level = logging.INFO
if args.verbose:
    log_level = logging.DEBUG
elif args.quiet:
    log_level = logging.WARNING
logging.basicConfig(
    format='%(asctime)s - %(levelname)s: %(message)s',
    filename=os.path.abspath(os.path.expanduser(args.log_file)),
    filemode='a', level=log_level
)

log_handler = logging.StreamHandler()
log_handler.setLevel(log_level)
log_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

log = logging.getLogger()
log.addHandler(log_handler)

log.info('Started')

# ==============================================================================
# Config file parser
# ==============================================================================
try:
    file_stat = os.stat(args.config)
except OSError as e:
    if e.errno == 2:
        log.critical('Config file "%s" does not exist', args.config)
        sys.exit(1)
    log.critical('File stat error -  %s', e)
    sys.exit(2)

if (stat.S_IRGRP | stat.S_IROTH) & file_stat.st_mode != 0:
    log.critical('Config file "%s" is group- or world-readable. Please '
                 '`chmod 400` or similar.',
                 args.config)
    sys.exit(3)

config = ConfigParser()
config.read_string('''
[imap]
[general]
folder=INBOX
''')

# Read config file and WARN if it has not been loaded
if len(config.read(args.config)) == 0:
    log.warn('Config file %s was not loaded', args.config)

# Overwrite the config values with the values provided via command line
for key in ('folder', 'script'):
    if getattr(args, key, None) is not None:
        config.set('general', key, getattr(args, key))

for key in ('host', 'user', 'password'):
    if getattr(args, key, None) is not None:
        config.set('imap', key, getattr(args, key))

# Check whether we should read password from stdin
if args.read_password:
    config.set('imap', 'password', getpass.getpass('Enter IMAP password: '))

critical_error = False

# Exit if there are config values missing
if len(config.get('general', 'folder')) == 0:
    log.critical('the folder must not be an empty string')
    critical_error = True

if not config.has_option('general', 'script'):
    log.critical('there is no script set')
    critical_error = True
else:
    config.set('general', 'script',
               os.path.abspath(os.path.expanduser(config.get('general',
                                                             'script'))))
    try:
        file_stat = os.stat(config.get('general', 'script'))
    except OSError as e:
        if e.errno == 2:
            log.critical('Script file "%s" does not exist',
                         config.get('general', 'script'))
        else:
            log.critical('File stat error -  %s', e)
        critical_error = True

if not config.has_option('imap', 'host'):
    log.critical('there is not imap host set')
    critical_error = True
if not config.has_option('imap', 'user'):
    log.critical('there is not imap user set')
    critical_error = True
if not config.has_option('imap', 'password'):
    log.critical('there is not imap password set')
    critical_error = True

if critical_error:
    sys.exit(1)

config.set('general', 'ignore',
           ','.join(map(str.strip, config.get('general', 'ignore').split(','))))

# ==============================================================================
# Load user supplied script which contains the sorting rules
# ==============================================================================
script_last_mtime = os.path.getmtime(config.get('general', 'script'))
log.debug('Inserting directory "%s" into sys.path',
          os.path.dirname(config.get('general', 'script')))
sys.path.insert(0, os.path.dirname(config.get('general', 'script')))

script_module_name = os.path.splitext(os.path.basename(config.get('general',
                                                                  'script'))
                                      )[0]
log.debug('Importing "%s"', script_module_name)
script_module = importlib.import_module(script_module_name)


# ==============================================================================
# Function to do the search based on the rules supplied by users
# ==============================================================================
def apply_rules(imap, rules):
    log = logging.getLogger()

    for folder, folder_rules in rules:
        if not folder_rules:
            continue

        search_rules = []
        for folder_rule in folder_rules:
            if search_rules:
                search_rules.insert(0, 'OR')

            if isinstance(folder_rule, str):
                search_rules.append(folder_rule)
            else:
                search_rules.extend(folder_rule)

        messages = imap.search(search_rules)
        log.debug('Found %d messages for filter "%s"', len(messages), folder)

        if not messages:
            continue

        copy_response = imap.copy(messages, folder)
        log.debug('Copied %d messages to folder "%s": %s', len(messages),
                  folder, copy_response)

        imap.delete_messages(messages)
        try:
            imap.expunge(messages)
        except TypeError:
            imap.expunge()
        log.info('Moved %d messages to folder "%s"', len(messages), folder)


def move_replies(imap, config):
    log = logging.getLogger()
    ignored_folders = config.get('general', 'ignore').split(',')

    result = imap.search(['HEADER', 'In-Reply-To', '@'])
    data = imap.fetch(result, ['ENVELOPE'])
    messages = defaultdict(set)
    envelopes = dict()
    for id_, message in data.items():
        envelope = message[b'ENVELOPE']
        envelopes[id_] = envelope
        messages[envelope.in_reply_to].add(id_)

    query = ['OR'] * (len(messages) - 1)
    query.extend(functools.reduce(
        operator.concat,
        (('HEADER', 'Message-ID', msg_id) for msg_id in messages.keys())
    ))

    log.debug('Found %d messages with In-Reply-To header', len(messages))

    def recursively_remove_message_tree(messages, envelopes, msg_ids):
        from queue import Queue

        ids = Queue()

        if not isinstance(msg_ids, list):
            ids.put(msg_ids)
        else:
            for msg_id in msg_ids:
                ids.put(msg_id)

        while not ids.empty():
            msg_id = ids.get()
            if msg_id not in messages:
                continue
            uids = messages[msg_id]
            del messages[msg_id]
            for uid in uids:
                for m_id in envelopes[uid].message_id:
                    ids.put(m_id)

    result = imap.search(query)
    to_delete = []
    data = imap.fetch(result, ['ENVELOPE'])
    for id_, message in data.items():
        envelope = message[b'ENVELOPE']
        if envelope.in_reply_to is None:
            # Neither this message nor all depending messages need to be
            # considered
            recursively_remove_message_tree(
                messages, envelopes, envelope.message_id)
        else:
            # Add all messages depending on this message to the message this
            # message depends on
            messages[envelope.in_reply_to].update(messages[envelope.message_id])
            messages[envelope.message_id] = messages[envelope.in_reply_to]
            to_delete.append(envelope.message_id)

    # number_of_messages_before = len(messages)

    for msg_id in to_delete:
        del messages[msg_id]

    if b'' in messages:
        del messages[b'']

    # log.debug('Ignored %d messages whose initial message is also in "%s"',
    #           len(functools.reduce(set.union, messages.values())) - number_of_messages_before,
    #           config.get('general', 'folder'))

    folders = imap.list_folders()
    for _, _, folder in folders:
        ignored = False
        for ignored_folder in ignored_folders:
            if folder.startswith(ignored_folder):
                ignored = True

        if ignored or folder == config.get('general', 'folder'):
            continue

        query = ['OR'] * (len(messages) - 1)
        query.extend(functools.reduce(
            operator.concat,
            (('HEADER', 'Message-ID', msg_id) for msg_id in messages.keys())
        ))

        imap.select_folder(folder)
        result = imap.search(query)

        if result:

            data = imap.fetch(result, ['ENVELOPE'])
            message_ids = list(message[b'ENVELOPE'].message_id for message in data.values())

            ids_to_move = list(functools.reduce(set.union, (messages[msg_id] for msg_id in message_ids)))

            imap.select_folder(config.get('general', 'folder'))
            copy_response = imap.copy(ids_to_move, folder)
            log.debug('Copied %d replies to folder "%s": %s', len(ids_to_move),
                      folder, copy_response)

            imap.delete_messages(ids_to_move)
            try:
                imap.expunge(ids_to_move)
            except TypeError:
                imap.expunge()
            log.info('Moved %d replies to folder "%s"', len(ids_to_move), folder)


def imap_login(config):
    log = logging.getLogger()

    # Connect to IMAP
    try:
        imap = imapclient.IMAPClient(host=config.get('imap', 'host'),
                                     use_uid=True,
                                     ssl=True)
        log.debug('Connected to IMAP host %s', config.get('imap', 'host'))
    except BaseException:
        log.critical(
            'Could not connect to IMAP host %s', config.get('imap', 'host')
        )
        sys.exit(1)
    try:
        imap.login(config.get('imap', 'user'), config.get('imap', 'password'))
        log.debug('Logged in on IMAP host as %s', config.get('imap', 'user'))
    except BaseException:
        log.critical(
            'Could not login on IMAP host as %s', config.get('imap', 'user')
        )
        sys.exit(1)

    try:
        folder = config.get('general', 'folder')
        imap.select_folder(folder)
    except BaseException:
        log.critical('Cannot select mailbox %s', folder)
        sys.exit(1)

    return imap


def imap_close(imap):
    log = logging.getLogger()

    # Disconnect from IMAP
    try:
        imap.close_folder()
        log.debug('Closed IMAP directory')
    except BaseException:
        log.warn('Could not close directory')
    try:
        imap.logout()
        log.debug('Logged out from IMAP')
    except Exception as e:
        log.warn('Could not log out from IMAP: %s', e)


# ==============================================================================
# Main program
# ==============================================================================
imap = imap_login(config)

try:
    apply_rules(imap, script_module.get_rules())
    move_replies(imap, config)
    while True:
        try:
            imap.idle()
            results = imap.idle_check(timeout=30)
            imap.idle_done()

            something_changed = False

            if script_last_mtime < os.path.getmtime(config.get('general',
                                                               'script')):
                script_last_mtime = os.path.getmtime(config.get('general',
                                                                'script'))
                log.info('Script "%s" changed, reloading', script_module_name)
                script_module = importlib.reload(script_module)
                something_changed = True

            for result in results:
                if result[1] != b'EXISTS':
                    continue
                something_changed = True

            if something_changed:
                apply_rules(imap, script_module.get_rules())
                move_replies(imap, config)

        except (imaplib.IMAP4.abort, TimeoutError, ConnectionResetError):
            log.warn('IMAP abort exception. Trying to reconnect...')
            imap_close(imap)
            imap = imap_login(config)

except KeyboardInterrupt:
    log.info('Program got CTRL+C interrupt. Exiting...')
    try:
        imap.idle_done()
    except BaseException:
        pass

imap_close(imap)

log.info('Finished')
