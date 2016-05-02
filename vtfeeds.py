#!/usr/bin/python

"""VirusTotal Threat Intelligence Gathering Script
Modified by: Lior Ben-Porat (RSA Security)

This script is used to sync-up with VirusTotal file/url feed API and store meta-data
of every submission to Virustotal in a MongoDB instance. This information can later
be utilized for threat intelligence gathering.
Make sure you run this script in a cronjob of 1 minute intervals in order to keep
a track of the live submissions on VirusTotal.
Before using this script use following commands in your MongoDB instance in order to
index the 'sha256' and 'url' fields for optimized query speeds:
db.file.createIndex({sha256:1})
db.url.createIndex({url:1})

Based on Emiliano Martinez example script used to interact with VirusTotal's
feeds APIs. (Copyright 2012 Google Inc.  All Rights Reserved)
The API is documented at:
https://www.virustotal.com/documentation/private-api/#file-feed
https://www.virustotal.com/documentation/private-api/#url-feed

Please contact VirusTotal to obtain a Private API key for this script to function properly.
"""

__author__ = 'Lior Ben-Porat (RSA Security)'
__version__ = '0.2'

import ConfigParser
import json
import logging
import os
import pymongo
import Queue
import requests
import socket
import sys
import tarfile
import threading
from datetime import datetime, timedelta


_FEEDS = [
    'file',
    'url',
    #'domain',
    #'ipaddress'
]
_FEEDS_URL = 'https://www.virustotal.com/vtapi/v2/%s/feed'
_MAX_RETRY_ATTEMPTS = 3
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024
_NUM_CONCURRENT_THREADS = 20
_THIS_PATH = os.path.dirname(os.path.abspath(__file__))
_LOCAL_PACKAGE_STORE = os.path.join(_THIS_PATH, 'vtpackages')
_DEFAULT_CONFIG_FILE = os.path.join(_THIS_PATH, 'vtfeeds.conf')
_DEFAULT_LOG_FILE = os.path.join(_THIS_PATH, 'vtfeeds.log')

_process_queue = Queue.Queue()
_mongo_collection = None

socket.setdefaulttimeout(10)

logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
LOGGING_LEVEL = logging.ERROR
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    #stream=sys.stdout,
                    filename=_DEFAULT_LOG_FILE)


def read_config(config_file, section_to_read):
    """Parse a configuration file in INI format into Dict."""
    config = ConfigParser.ConfigParser()
    config.read(config_file)
    conf_dict = {}
    try:
        options = config.options(section_to_read)
    except ConfigParser.NoSectionError:
        logging.error(
            'Invalid section "%s" in config file: %s', section_to_read, config_file)
        return
    for option in options:
        conf_dict[option] = config.get(section_to_read, option)
    return conf_dict


def mongo_connect(host, port, database, collection, username, password):
    """Retrieve a collection from a given MongoDB instance."""
    global _mongo_collection
    try:
        client = pymongo.MongoClient(host, port)
    except pymongo.errors.ConnectionFailure, e:
        logging.error('Could not connect to MongoDB: %s', e)
        return
    if username and password:
        client[database].authenticate(username, password)
    db = client[database]
    _mongo_collection = db[collection]


def create_package_store(feed):
    """Directory to store feed time window packages retrieved from VirusTotal."""
    if not os.path.exists(_LOCAL_PACKAGE_STORE):
        os.mkdir(_LOCAL_PACKAGE_STORE)
    feed_package_path = os.path.join(_LOCAL_PACKAGE_STORE, feed)
    if not os.path.exists(feed_package_path):
        os.mkdir(feed_package_path)


def get_submission(item_report):
    """Build a dictionary of the submission info inside each record"""
    submission = item_report.get('submission')
    submission.update({'positives': item_report.get('positives')})
    submission.update({'total': item_report.get('total')})
    return submission


def process_file_report(item_report):
    """Create a record per file report in MongoDB collection."""
    global _mongo_collection
    _FIELDS_SET_1 = [
        'md5',
        'sha1',
        'sha256',
        'type',
        'size',
        'tags',         # list
        'first_seen',
    ]
    _FIELDS_SET_2 = [
        'times_submitted',
        'unique_sources',
        'community_reputation',
        'harmless_votes',
        'malicious_votes',
        'submission_names', # list
        'ITW_urls',         # list
    ]
    try:
        # Avoid private API rescans by checking the existence of submission value
        if item_report.get('submission'):
            query = {'sha256': item_report.get('sha256')}
            find_result = _mongo_collection.find_one(query)
            # Add new record
            if not find_result:
                new_record = {}
                new_record['submissions_count'] = 1
                for field in _FIELDS_SET_1 + _FIELDS_SET_2:
                    new_record[field] = item_report.get(field)
                new_record['submissions'] = [get_submission(item_report),]
                _mongo_collection.insert_one(new_record)
                return True
            # Add submission to existing record
            update_result = _mongo_collection.update_one(
                {'_id': find_result['_id']},
                {'$addToSet': {'submissions': get_submission(item_report)}}
            )
            # Increase the submissions_count field by one
            if update_result.modified_count:
                _mongo_collection.update_one(
                    {'_id': find_result['_id']},
                    {'$inc': {'submissions_count': 1}}
                )
            # Update existing record
            update_dict = {}
            for field in _FIELDS_SET_2:
                update_dict.update({field: item_report.get(field)})
            _mongo_collection.update_one(
                {'_id': find_result['_id']},
                {'$set': update_dict}
            )
        return True
    except:
        return False


def process_url_report(item_report):
    """Create a record per url report in MongoDB collection."""
    global _mongo_collection
    try:
        # Avoid private API rescans by checking the existence of submission value
        if item_report.get('submission'):
            query = {'url': item_report.get('url')}
            find_result = _mongo_collection.find_one(query)
            # Add new record
            if not find_result:
                new_record = {}
                new_record['url'] = item_report.get('url')
                new_record['first_seen'] = item_report.get('first_seen')
                new_record['last_seen'] = item_report.get('last_seen')
                new_record['resp_code'] = item_report.get('additional_info').get('Response code')
                new_record['resp_hash'] = item_report.get('additional_info').get('Response content SHA-256')
                new_record['ip_resolution'] = item_report.get('resolution')
                new_record['ip_country'] = item_report.get('resolution_country')
                new_record['submissions_count'] = 1
                new_record['submissions'] = [get_submission(item_report),]
                _mongo_collection.insert_one(new_record)
                return True
            # Add submission to existing record
            update_result = _mongo_collection.update_one(
                {'_id': find_result['_id']},
                {'$addToSet': {'submissions': get_submission(item_report)}}
            )
            # Increase the submissions_count field by one
            if update_result.modified_count:
                _mongo_collection.update_one(
                    {'_id': find_result['_id']},
                    {'$inc': {'submissions_count': 1}}
                )
        return True
    except:
        return False


def file_feed_handler():
    """Worker that handle individual files found within the file feed."""
    while True:
        item_report = _process_queue.get()
        success = process_file_report(item_report)
        if success:
            logging.info('Successfully processed file %s', item_report.get('sha256'))
        else:
            logging.error('Unable to processed file %s', item_report.get('sha256'))
        _process_queue.task_done()


def url_feed_handler():
    """Worker that handle individual urls found within the url feed."""
    while True:
        item_report = _process_queue.get()
        success = process_url_report(item_report)
        if success:
            logging.info('Successfully processed URL %s', item_report.get('url'))
        else:
            logging.error('Unable to processed URL %s', item_report.get('url'))
        _process_queue.task_done()


def launch_feed_handlers(feed):
    """Set up feed handling threads."""
    handler_func = '%s_feed_handler' % feed
    threads = []
    for _ in range(_NUM_CONCURRENT_THREADS):
        thread = threading.Thread(target=globals()[handler_func])
        thread.daemon = True
        thread.start()
        threads.append(thread)
    return threads


def download_to_file(url, destination):
    """Stream download the response of a given URL to a local file."""
    for _ in range(_MAX_RETRY_ATTEMPTS):
        try:
            response = requests.get(url, stream=True)
            if response.status_code != 200:
                logging.error(
                    'Unable to download to %s, URL answered with status code: %s',
                    destination, response.status_code)
                return
            with open(destination, 'wb') as destination_file:
                for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_SIZE):
                    if chunk:  # filter out keep-alive new chunks
                        destination_file.write(chunk)
            return destination
        except:  # pylint: disable=bare-except
            continue


def get_package(package, api_key, feed):
    """Retrieve a time window feed reports package from VirusTotal."""
    package_url = _FEEDS_URL % (feed) + '?package=%s&apikey=%s' % (
        package, api_key)
    destination = os.path.join(
        _LOCAL_PACKAGE_STORE, feed, '%s.tar.bz2' % (package))
    return download_to_file(package_url, destination)


def get_item_type(item_report):
    """Given a feed item report induce whether it is a file, URL, domain, etc."""
    permalink = item_report.get('permalink') or ''
    if '/file/' in permalink:
        return 'file'
    elif '/url/' in permalink:
        return 'url'


def process_feed_item(item_report):
    """Process an individual item report contained within a feed package."""
    # Can add filtering rules here to avoid specific submissions
    item_type = get_item_type(item_report)
    if item_type == 'file':
        _process_queue.put(item_report)
    elif item_type == 'url':
        _process_queue.put(item_report)


def process_package(package_path):
    """Process a time window feed package retrieved from VirusTotal."""
    with tarfile.open(package_path, mode='r:bz2') as compressed:
        for member in compressed.getmembers():
            member_file = compressed.extractfile(member)
            for line in member_file:
                item_json = line.strip('\n')
                if not item_json:
                    continue
                item_report = json.loads(item_json)
                process_feed_item(item_report)


def main():
    """Pipeline the entire feed processing logic."""
    if len(sys.argv) != 2:
        print '''Usage:
        %s <feed>\n''' % sys.argv[0]
        return
    feed = sys.argv[1]
    # Check that the requested feed does indeed exist.
    if feed not in _FEEDS:
        logging.error(
            'Invalid feed requested, should be one of: %s', ', '.join(_FEEDS))
        return
    settings = read_config(_DEFAULT_CONFIG_FILE, 'Settings')
    # Set the package format required by VirusTotal
    package = datetime.strftime(datetime.now() - timedelta(hours=int(settings.get('time_delta'))), '%Y%m%dT%H%M')
    # Set up a connection with MongoDB server
    mongo_connect(
        settings.get('mongo_host'),
        int(settings.get('mongo_port')),
        settings.get('mongo_db'),
        feed,
        settings.get('mongo_user'),
        settings.get('mongo_pass'),
    )
    # The time window feed package is temporarily stored to a given directory, and
    # processed from there.
    create_package_store(feed)
    launch_feed_handlers(feed)
    # Download the compressed package with all the items processed by VirusTotal
    # during the time window being requested.
    logging.info('Fetching package file with timestamp: %s', package)
    package_path = get_package(package, settings.get('api_key'), feed=feed)
    if not package_path:
        logging.error('Failed to download feed package')
        return
    process_package(package_path)
    _process_queue.join()
    # We delete the time window feed package. If you need to keep these report
    # buckets you should comment out this line and rather store the packages in
    # a n-level directory structure or persistent storage.
    if package_path and os.path.exists(package_path):
        os.remove(package_path)


if __name__ == '__main__':
    main()
