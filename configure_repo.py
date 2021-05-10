#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import sys
import argparse
from datetime import date, datetime, timedelta
import time
from os.path import dirname, abspath
import re

try:
    from elasticsearch import Elasticsearch
except Exception as e:
    print("No module 'elasticsearch' found.")
    sys.exit()

def read_elatic_config(auth_path):
    return json.load(open(auth_path))


def read_snapshots_conf(conf_path):
    return json.load(open(conf_path))

def log(msg):
    now_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    final_msg = "{0} wazuh-snapshot: {1}".format(now_date, msg)
    print(final_msg)
    if output_file:
        foutput.write(final_msg + "\n")

def create_repo(repo_config):
    try:
        if repo_config['repository_type'] == "local":
            body_data = { "type": "fs", "settings": { "location": repo_config['repository'] } }

        elif repo_config['repository_type'] == "s3":
            body_data = { "type": repo_config['repository_type'], "settings": { "bucket": repo_config['bucket'], "region": repo_config['region'], "base_path": repo_config['base_path'] } }

        es.snapshot.create_repository(repository=repo_config['repository'],body=body_data)

    except Exception as e:
        log("Error: {0}: {1}".format(repo_config['repository'], str(e)))
        sys.exit()

if __name__ == "__main__":
    # Args
    parser = argparse.ArgumentParser(description='Create snapshots repository Elastic')
    parser.add_argument('-o', '--output_file', metavar='output_file', type=str, required = False, help='Output filename.')
    args = parser.parse_args()

    # Vars
    current_path = dirname(abspath(__file__))
    SLEEP_TIME = 10
    LOG_ITERATIONS = 5
    output_file = None
    if args.output_file:
        output_file = args.output_file
        foutput = open(output_file, 'a')

    # Config
    config = read_snapshots_conf('{0}/snapshots_conf.json'.format(current_path))
    es_conf = read_elatic_config(config['es_config_path'])
    repo_type = config['repository_type']

    if es_conf['settings']['elasticsearch']['auth'] == 'True':
        http_auth_value=(es_conf['credentials']['elasticsearch']['user'], es_conf['credentials']['elasticsearch']['pass'])
    else:
        http_auth_value=False

    # Elastic connectivity
    es = Elasticsearch(
        [es_conf['settings']['elasticsearch']['hostname']],
        http_auth=http_auth_value,
        port=es_conf['settings']['elasticsearch']['port'],
        ca_certs=es_conf['settings']['elasticsearch']['ca_cert'],
        use_ssl=es_conf['settings']['elasticsearch']['use_ssl'],
    )

    try:
        create_repo(config)
    except Exception as e:
        print("  Elasticsearch error: {0}".format(str(e)))
        sys.exit(1)

    if output_file:
        foutput.close()
