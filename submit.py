#!/usr/bin/env python
# This file is part of 
# Maltracker - Malware analysis and tracking platform
# http://www.maltracker.net
# http://www.anubisnetworks.com
#
# Copyright (C) 2014-2015 AnubisNetworks, NSEC S.A.
# Copyright (C) 2013-2014 Valter Santos.
# See the file 'docs/LICENSE' for copying permission.


import argparse
import urllib2
import base64
import logging
import sys
import os
import json
from datetime import datetime, timedelta

from urlparse import urlparse, urlunparse

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "lib"))
from maltracker.common.formdata import encode_multipart
from maltracker.common.file import File

MALTRACKER_SERVER = "http://api.maltracker.net:4700"
MALTRACKER_APIKEY = None

def main():
 
    global MALTRACKER_SERVER
    global MALTRACKER_APIKEY

    server = MALTRACKER_SERVER
    api_key = MALTRACKER_APIKEY
    target = None
    task_type = None
    rename = False
    force = False
    tags = ''
    options = ''
    url_file = None
    platform = 'winxp'
    timeout = None
    burst = None
    sleep = None
    pets = None
    memory = False

    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)

    parser = argparse.ArgumentParser(description="Maltracker submit utility")
    parser.add_argument("-k", "--apikey", help="Maltracker API Key", required=False)
    parser.add_argument("-s", "--server", help="Maltracker server", required=False)
    parser.add_argument("-f", "--file", help="File to submit", required=False)
    parser.add_argument("-p", "--path", help="Path to submit (all files)", required=False)
    parser.add_argument("-u", "--url", help="URL to submit", required=False)
    parser.add_argument("-uF", "--urlfile", help="File with URLs to submit", required=False)    
    parser.add_argument("-r", "--rename", help="automatically rename files to MD5", required=False, action='store_true')
    parser.add_argument("--force", help="Forces analysis to start even if the file was already analysed", required=False, action='store_true')
    parser.add_argument("--platform", help="Platform to run the analysis (winxp/win7)", required=False)
    parser.add_argument("--timeout", help="Analysis timeout in minutes", required=False)
    parser.add_argument("--memory", help="Dumps and processes memory from the analysis system", required=False, action='store_true')
    parser.add_argument("-t", "--tags", help="Tags the analysis", required=False)
    parser.add_argument("-o", "--options", help="Advanced options to pass to the analysis engine", required=False)
    parser.add_argument("--burst", help="With -p, number of files to submit before sleeping (see --sleep)", required=False)
    parser.add_argument("--sleep", help="With -p, number of seconds to sleep between bursts", required=False)
    parser.add_argument("--pets", help="Only submit if is a PE and compilation timestamp is N days older", required=False)

    args = parser.parse_args()
    if args.apikey:
        api_key = args.apikey
    if args.server:
        server = args.server

    if args.file:
        task_type = "file"
        target = args.file
    elif args.path:
        task_type = "dir"
        target = args.path
        if args.burst:
            burst = args.burst
        if args.sleep:
            sleep = args.sleep
    elif args.url:
        task_type = "url"
        target = args.url
    elif args.urlfile:
        task_type = "url"
        url_file = args.urlfile
    else:
        logging.error("No file or url to submit.")
        sys.exit(1)

    if args.rename:
        rename = True

    if args.force:
        force = True

    if args.platform in ['winxp', 'win7']:
        platform = args.platform

    if args.memory:
        memory = True

    if args.tags:
        tags = args.tags

    if args.options:
        options = args.options

    if args.timeout:
        timeout = int(args.timeout)

    if task_type in ['dir', 'file'] and args.pets:
        pets = args.pets


    if (not (server or MALTRACKER_SERVER)):
        logging.error("No Maltracker server defined")
        sys.exit(1)
    elif (not (api_key or MALTRACKER_APIKEY)):
        logging.error("API Key not entered")
        sys.exit(1)

    if task_type == "dir":
        task_type = "file"
        if os.path.isdir(target):
            files = [ os.path.join(target,f) for f in os.listdir(target) if os.path.isfile(os.path.join(target,f)) ]
            logging.info("Submitting %s files from path %s" % (len(files), target))
            if burst:
                logging.info("Burst: %s, Sleep: %s seconds" % (burst, sleep))
            i = 0
            for f in files:
                try:
                    submit( target=f, 
                            server=server, 
                            api_key=api_key, 
                            task_type=task_type, 
                            rename=rename, 
                            force=force, 
                            platform=platform, 
                            memory=memory,
                            tags=tags, 
                            options=options,
                            timeout=timeout,
                            pets=pets,
                        )
                except:
                    pass
                i = i + 1
                if burst and sleep:
                    if i % int(burst):
                        time.sleep(int(sleep))
        else:
            logging.error("Invalid path %s" % target)

    elif task_type == "url" and url_file is not None:
        try:
            with open(url_file) as fp:
                for line in fp:
                    target = line.strip()
                    try:
                        submit( target=target, 
                                server=server, 
                                api_key=api_key, 
                                task_type=task_type, 
                                rename=rename, 
                                force=force, 
                                platform=platform, 
                                memory=memory,
                                tags=tags, 
                                options=options,
                                timeout=timeout,
                            )
                    except Exception as e:
                        logging.error("Can't submit %s: %s" % (target, str(e)))
        except Exception as e:
            logging.error("Error reading file %s: %s" % (url_file, str(e)))

    else:
        submit( target=target, 
                server=server, 
                api_key=api_key, 
                task_type=task_type, 
                rename=rename, 
                force=force, 
                tags=tags,
                platform=platform, 
                memory=memory,
                options=options,
                timeout=timeout,
                pets=pets)
    


def submit(target=None, server=None, api_key=None, task_type='file', rename=False, force=False, platform='winxp', memory=False, tags=None, options=None, timeout=None, pets=None):
    try:
        fields = dict()
        fields['apikey'] = api_key

        if task_type == 'file':

            if not os.path.isfile(target):
                logging.error("%s does not exists" % target)
                return False

            fields['base64_encoded'] = False

            if force:
                fields['force'] = True

            if tags:
                fields['tags'] = tags

            if options:
                fields['opt'] = options

            if platform:
                fields['platform'] = platform

            if memory:
                fields['memdump'] = memory

            if timeout:
                fields['timeout'] = timeout
                fields['enforce'] = True

            fh = open(target, 'rb')
            fobj = File(target, fh.read())

            # if pets is on, check if is a PE and if compile timestamp in recent
            if pets:
                ftype = fobj.get_package(file_type=fobj.get_type())
                if ftype in ['exe', 'dll']:
                    ts = fobj.get_timestamp(is_pe=True)
                    if  datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') < (datetime.now() - timedelta(int(pets))):
                        logging.info("%s %s not submitted. Compilation time is to old (%s)." % (task_type, target, ts))
                        return False
                    else:
                        logging.debug("%s %s compilation time %s" % (task_type, target, ts))
                else:
                    logging.info("%s %s (%s) is not a PE" % (task_type, target, ftype))
                    return False

            if rename:
                filename = fobj.get_md5()
            else:
                filename = fobj.get_name()

            files = { 'file': { 'filename': filename, 'content': fobj.get_data()}}
            fh.close()

            data, headers = encode_multipart(fields, files)
            request = urllib2.Request('%s/task/submit/file/' % (server), data=data, headers=headers)

        else:
            # task = url

            # convert url to IDN
            if not (target.startswith("http://", 0) or target.startswith("https://", 0)):
                target = "http://" + target
            o = urlparse(target)
            target = urlunparse([o.scheme, o.netloc.decode("utf8").encode("idna"), o.path, o.params, o.query, o.fragment])

            fields['url'] = target

            if force:
                fields['force'] = True

            if tags:
                fields['tags'] = tags

            if options:
                fields['opt'] = options

            data, headers = encode_multipart(fields, {})
            request = urllib2.Request('%s/task/submit/url/' % (server), data=data, headers=headers)

        request.add_header('User-Agent', "Maltracker submit utility")
        response = urllib2.urlopen(request).read()
        responsedata = json.loads(response)         

        if 'error' in responsedata:
            logging.error("%s" % responsedata['error'])
        else:
            logging.info("%s %s (%s) submitted to maltracker" % (task_type, target, responsedata['target']['md5']))

    except Exception as e:
        logging.error("Problem connecting. Please Try again.")
        logging.exception(e)
 


if __name__ == "__main__":
    main()
    
