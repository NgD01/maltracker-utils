#!/usr/bin/env python
# This file is part of 
# Maltracker - Malware analysis and tracking platform
# http://www.maltracker.net
# http://www.anubisnetworks.com
#
# Copyright (C) 2015 AnubisNetworks, NSEC S.A.
# See the file 'docs/LICENSE' for copying permission.

import argparse
import urllib2
import logging
import logging.handlers
import sys
import os
import json

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "lib"))
from maltracker.common.formdata import encode_multipart
from maltracker.common.file import File

MALTRACKER_SERVER = "http://api.maltracker.net:4700"
MALTRACKER_APIKEY = None
FILELIST = dict()

FILESIZE_LIMIT = 33554432

log = logging.getLogger()

def main():
 
    global MALTRACKER_SERVER
    global MALTRACKER_APIKEY

    server = MALTRACKER_SERVER
    apikey = MALTRACKER_APIKEY
    target = None
    task_type = None
    rename = False
    force = False
    tags = ''
    options = ''
    url_file = None
    platform = 'winxp'
    timeout = None
    title = None
    nosubmit = False
    nowait = False
    onlyexe = False
    infected_files = dict()


    init_logging()

    parser = argparse.ArgumentParser(description="Maltracker scan utility")
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-k", "--apikey", help="Maltracker API Key", required=False)
    parser.add_argument("-s", "--server", help="Maltracker server", required=False)
    parser.add_argument("-f", "--file", help="File to submit", required=False)
    parser.add_argument("-p", "--path", help="Path to submit (all files)", required=False)
    parser.add_argument("-t", "--title", help="Analysis title", required=False)
    parser.add_argument("-nS", "--nosubmit", action="store_true", help="Don't submit files to maltracker, just check if they were already analyzed", required=False)
    parser.add_argument("-exe", action="store_true", help="Only submit PE EXE files to maltracker")
    parser.add_argument("-nW", "--nowait", action="store_true", help="Dont wait to analyses to complete on maltracker")

    args = parser.parse_args()

    if args.apikey:
        apikey = args.apikey
    elif MALTRACKER_APIKEY:
        apikey = MALTRACKER_APIKEY
        
    if args.server:
        server = args.server
    elif MALTRACKER_SERVER:
        server = MALTRACKER_SERVER

    if (not (server or MALTRACKER_SERVER)):
        logging.error("No Maltracker server defined")
        sys.exit(1)
    elif (not (apikey or MALTRACKER_APIKEY)):
        logging.error("API Key not entered")
        sys.exit(1)

    if args.file:
        task_type = "file"
        target = args.file
    elif args.path:
        task_type = "dir"
        target = args.path
    else:
        logging.error("No file or url to submit.")
        sys.exit(1)

    if args.quiet:
        log.setLevel(logging.WARN)
    elif args.debug:
        log.setLevel(logging.DEBUG)

    if args.title:
        title = args.title

    if args.nosubmit:
        nosubmit = True

    if args.nowait:
        nowait = True

    if args.exe:
        onlyexe = True

    log.info("Scanning valid files on %s" % target)

    total_files = reduce_files_type(target)
    valid_files =len(FILELIST)
    log.info("%s files with allowed type from %s total files" % (valid_files, total_files))

    knowngood_files = reduce_files_good(target_path=target)

    log.info("Ignoring %s files that are known good files" % knowngood_files)

    analyze_files = len(FILELIST)
    # check already scanned files on maltracker
    log.info("Checking on maltracker if %s files were previously analyzed" % (analyze_files))

    malrep = check_maltracker_reports(server=server, apikey=apikey, hashes=FILELIST.keys())

    for md5,report in malrep.iteritems():
        if len(report['antivirus']):
            report['filename'] = FILELIST[md5].replace(target, '')
            infected_files[md5] = report
        del FILELIST[md5]

    # submit reduced files to maltracker
    if not nosubmit:
        if onlyexe:
            tosubmit = list()
            for md5,filename in FILELIST.iteritems():
                if filename.endswith(".exe"):
                    tosubmit.append(filename)

            log.info("Will submit %s files to maltracker" % len(tosubmit))
            for s in tosubmit:
                submit_maltracker(server=server, apikey=apikey, target=s, force=True)

        # waits for all analyses to complete
        if not nowait:
            pass
        else:
            pass


    # print overwall analysis summary
    if len(infected_files):
        result = "INFECTED"
    else:
        result = "NOT INFECTED"

    log.info(" == ANALYSIS SUMMARY:")
    log.info(" == Result: %s  %s" % (result, title))
    log.info(" == Total files: %s" % total_files)
    log.info(" == Valid files: %s" % valid_files)
    log.info(" == Known Good files: %s" % knowngood_files)
    log.info(" == Analized files: %s" % analyze_files)
    log.info(" == Infected files: %s" % len(infected_files))

    for md5,report in infected_files.iteritems():
        log.info("\t    %s" % (report['filename']))
        log.info("\t    MD5: %s Permalink: %s" % (md5, report['permalink']) )
        for name,value in report['antivirus'].iteritems():
            log.info("\t\t%s: %s" % (name,value))


def init_logging(logfile=os.path.join("logs", "scan.log")):
    """Initializes logging."""
    global log
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    fh = logging.handlers.WatchedFileHandler(logfile)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(logging.INFO)


def reduce_files_type(target_path=None):
    """ reduce file list to file types allowed by maltracker
    """

    global FILELIST
    i = 0
    for path, subdirs, files in os.walk(target_path):
        for name in files:
            fn = os.path.join(path, name)
            if valid_package(filename=fn):
                f = File(fn)
                FILELIST[f.get_md5()] = os.path.join(path, name)
            i = i + 1

    return i


def reduce_files_good(target_path=None):
    """ reduce files based on known good hashsets
    """
    global FILELIST
    i = 0
    kgcount = 0
    delkeys = list()

    log.info("Checking for known good files")

    for md5,filename in FILELIST.iteritems():

    	url = "http://bin-test.shadowserver.org/api?md5=" + md5
    	req = urllib2.Request(url)
    	response = urllib2.urlopen(req)
    	kgreport = response.read()

    	if kgreport.rstrip() == md5:
    		log.debug("%s is not a known good file" % filename.replace(target_path, ''))
    	else:
    		# known good
    		try:
    			kgr = kgreport.replace(md5 + " ", '').strip()
    			jsonrep = json.loads(kgr.replace("\\",""), strict=False)
    			log.debug("%s is known good file from %s - %s (%s)" % (filename.replace(target_path, ''), jsonrep['product_name'], jsonrep['os_name'], jsonrep['mfg_name']))
    			delkeys.append(md5)
    		except Exception as e:
    			log.debug("%s" % kgreport)
    			log.debug("Error: %s" % str(e))

    		kgcount = kgcount + 1

    	i = i + 1

    for d in delkeys:
        del FILELIST[d]

    return kgcount


def valid_package(filename=None, file_type=None):
    """ check if file has a valid mimetype and is suitable for analysis
    """
    f = File(file_path=filename)
    if filename and not file_type:
        file_type = f.get_type()

    if not file_type:
        return None

    if f.get_size() > FILESIZE_LIMIT:
        return None

    if "DLL" in file_type and filename.endswith(".cpl"):
        return "cpl"
    elif "DLL" in file_type:
        return "dll"
    elif "PE32" in file_type or "MS-DOS" in file_type:
        return "exe"
    elif "PDF" in file_type:
        return "pdf"
    elif "Rich Text Format" in file_type or "Microsoft Office Word" in file_type or filename.endswith(".docx"):
        return "doc"
    elif "Microsoft Office Excel" in file_type or "Microsoft Excel" in file_type or filename.endswith(".xlsx"):
        return "xls"
    elif "Zip archive" in file_type:
        return "zip"
    elif "HTML" in file_type:
        return "html"
    else:
        return None


def check_maltracker_reports(server=None, apikey=None, hashes=None):
    """ checks if maltracker has reports for the given hashes
    """
    reports = dict()
    for h in hashes:
        try:
            rep =  get_maltracker_report(server, apikey, h)
            if not 'error' in rep:
                log.debug("Maltracker report for %s completed" % h)
                reports[h] = rep
            else:
                log.debug("No maltracker report for %s" % h)

        except Exception as e:
            log.debug("Error getting report: %s" % str(e))

    return reports

def get_maltracker_report(server=None, apikey=None, shash=None):
    """ gets a maltracker report """

    url = server + "/report/min/get/" + shash + "/?apikey=" + apikey
    req = urllib2.Request(url)
    response = urllib2.urlopen(req)
    report = json.loads(response.read())
    return report 



def submit_maltracker(server=None, apikey=None, target=None, force=False, platform='winxp'):
    try:
        fields = dict()
        fields['apikey'] = apikey

        if not os.path.isfile(target):
            logging.error("%s does not exists" % target)
            return False

        fields['base64_encoded'] = False

        if force:
            fields['force'] = True

        if platform:
            fields['platform'] = platform

        fh = open(target, 'rb')
        fobj = File(target, fh.read())
        filename = fobj.get_name()

        files = { 'file': { 'filename': filename, 'content': fobj.get_data()}}
        fh.close()

        data, headers = encode_multipart(fields, files)
        request = urllib2.Request('%s/task/submit/file/' % (server), data=data, headers=headers)


        request.add_header('User-Agent', "Maltracker scan utility")
        response = urllib2.urlopen(request).read()
        responsedata = json.loads(response)         

        if 'error' in responsedata:
            log.error("%s" % responsedata['error'])
        else:
            log.info("File %s (%s) submitted to maltracker" % (target, responsedata['target']['md5']))

    except Exception as e:
        log.error("Problem connecting: %s" % str(e))
 

if __name__ == "__main__":
    main()
