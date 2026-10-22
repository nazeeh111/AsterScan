#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
#  AsterScan signature updater (derived from LOKI Upgrader)
try:
 from urllib2 import urlopen
except ImportError:
 from urllib.request import urlopen #For python 3.5
import json
import zipfile
import shutil
import tempfile
import io
import os
import argparse
import traceback
import hashlib
from sys import platform as _platform
try:
    from urlparse import urlparse 
except ImportError:
    from urllib.parse import urlparse
from os.path import exists

# Win32 Imports
if _platform == "win32":
    try:
        import win32api
    except Exception:
        platform = "linux"  # crazy guess


from lib.lokilogger import *

# Platform
platform = ""
if _platform == "linux" or _platform == "linux2":
    platform = "linux"
elif _platform == "darwin":
    platform = "macos"
elif _platform == "win32":
    platform = "windows"

def cache_path(sig_url, cache_dir):
    path = urlparse(sig_url).path.split('/')[:-2]
    return os.path.join(cache_dir, '_'.join(path) + '.cache')


def needs_update(sig_url, cache_dir=None):
    try:
        o=urlparse(sig_url)
        path=o.path.split('/')
        branch=path[4].split('.')[0]
        path.pop(len(path)-1)
        path.pop(len(path)-1)
        url = o.scheme+'://api.'+o.netloc+'/repos'+'/'.join(path)+'/commits/'+branch
        response_info = urlopen(url)
        j = json.load(response_info)
        sha=j['sha']
        cache=cache_path(sig_url, cache_dir or os.getcwd())
        if exists(cache):
            with open(cache, "r") as file:
                old_sha = file.read().rstrip()
            return sha != old_sha, cache, sha
        return True, cache, sha
    except Exception:
        return True, None, None


class LOKIUpdater(object):

    # Incompatible signatures
    INCOMPATIBLE_RULES = []

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]
    
    UPDATE_URL_LOKI = "https://api.github.com/repos/nazeeh111/AsterScan/releases/latest"
    
    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = application_path

    @staticmethod
    def file_hash(path):
        digest = hashlib.sha256()
        with open(path, 'rb') as content:
            for chunk in iter(lambda: content.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def load_manifest(cache):
        try:
            with open(cache + '.manifest.json', 'r') as manifest_file:
                manifest = json.load(manifest_file)
            files = manifest['files']
            if not isinstance(files, dict) or not files or not isinstance(manifest['sha'], str):
                return None
            for relative_path, digest in files.items():
                parts = relative_path.split('/')
                if len(parts) != 2 or parts[0] not in ('iocs', 'yara', 'misc') or not parts[1] or \
                        parts[1] in ('.', '..') or '\\' in parts[1] or ':' in parts[1] or \
                        not isinstance(digest, str) or len(digest) != 64 or \
                        any(character not in '0123456789abcdef' for character in digest):
                    return None
            return manifest
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def manifest_matches(self, manifest, sha, sig_dir):
        if manifest is None or manifest['sha'] != sha:
            return False
        try:
            return all(self.file_hash(os.path.join(sig_dir, *relative_path.split('/'))) == digest
                       for relative_path, digest in manifest['files'].items())
        except OSError:
            return False

    def validate_yara_rules(self, staged_dir):
        try:
            import yara
        except ImportError:
            self.logger.log("NOTICE", "Upgrader", "yara-python unavailable; staged YARA rules were not compiled")
            return

        sources = []
        for subdir in ('yara', os.path.join('iocs', 'yara'), '3rdparty'):
            for root, _, files in os.walk(os.path.join(staged_dir, subdir)):
                for name in sorted(files):
                    if name.lower().endswith(('.yar', '.yara')) and not name.startswith(('.', '~', '_')):
                        with open(os.path.join(root, name), 'r') as rule_file:
                            sources.append(rule_file.read())
        if sources:
            yara.compile(source='\n'.join(sources), externals={
                'filename': '', 'filepath': '', 'extension': '', 'filetype': '',
                'md5': '', 'owner': '',
            })

    def update_signatures(self, clean=False):
        sig_dir = os.path.join(self.application_path, 'signature-base')
        stage_root = None
        preserve_stage = False
        pending_caches = []
        seen_targets = {}
        try:
            sources = []
            owners = {}
            for sig_url in self.UPDATE_URL_SIGS:
                changed, cache, sha = needs_update(sig_url, self.application_path)
                old_manifest = self.load_manifest(cache_path(sig_url, self.application_path))
                for relative_path in old_manifest['files'] if old_manifest else ():
                    target_key = relative_path.casefold()
                    if target_key in owners and owners[target_key] != sig_url:
                        raise ValueError("Signature target owned by multiple sources: %s" % relative_path)
                    owners[target_key] = sig_url
                sources.append((sig_url, clean or changed or not self.manifest_matches(old_manifest, sha, sig_dir),
                                cache, sha, old_manifest))

            for sig_url, changed, cache, sha, old_manifest in sources:
                if not changed:
                    self.logger.log("INFO", "Upgrader", "%s is up to date." % sig_url)
                    continue

                self.logger.log("INFO", "Upgrader", "Downloading %s ..." % sig_url)
                with urlopen(sig_url) as response:
                    with zipfile.ZipFile(io.BytesIO(response.read())) as zip_update:
                        bad_member = zip_update.testzip()
                        if bad_member:
                            raise zipfile.BadZipFile("Corrupt signature archive member: %s" % bad_member)

                        if stage_root is None:
                            stage_root = tempfile.mkdtemp(prefix='.asterscan-signatures-', dir=self.application_path)
                            staged_dir = os.path.join(stage_root, 'signature-base')
                            if os.path.isdir(sig_dir) and not clean:
                                shutil.copytree(sig_dir, staged_dir)
                            else:
                                os.makedirs(staged_dir)
                            for out_dir in ('iocs', 'yara', 'misc'):
                                os.makedirs(os.path.join(staged_dir, out_dir), exist_ok=True)

                        if old_manifest:
                            for relative_path in old_manifest['files']:
                                old_file = os.path.join(staged_dir, *relative_path.split('/'))
                                if os.path.isfile(old_file):
                                    os.remove(old_file)

                        accepted_count = 0
                        new_files = {}
                        for zip_path in zip_update.namelist():
                            sig_name = os.path.basename(zip_path)
                            if zip_path.endswith('/') or any(sig_name.endswith(rule) for rule in self.INCOMPATIBLE_RULES):
                                continue
                            if '/iocs/' in zip_path and zip_path.endswith('.txt'):
                                target_dir = 'iocs'
                            elif '/yara/' in zip_path and zip_path.endswith('.yar'):
                                target_dir = 'yara'
                            elif '/misc/' in zip_path and zip_path.endswith('.txt'):
                                target_dir = 'misc'
                            elif zip_path.endswith('.yara'):
                                target_dir = 'yara'
                            else:
                                continue
                            relative_path = target_dir + '/' + sig_name
                            target_key = relative_path.casefold()
                            if target_key in seen_targets:
                                raise ValueError("Signature target collision: %s and %s" %
                                                 (seen_targets[target_key], zip_path))
                            if target_key in owners and owners[target_key] != sig_url:
                                raise ValueError("Signature target collision with another source: %s" % relative_path)
                            seen_targets[target_key] = zip_path
                            target_file = os.path.join(staged_dir, target_dir, sig_name)
                            self.logger.log("DEBUG", "Upgrader", "Extracting %s ..." % zip_path)
                            with zip_update.open(zip_path) as source, open(target_file, 'wb') as target:
                                shutil.copyfileobj(source, target)
                            new_files[relative_path] = self.file_hash(target_file)
                            accepted_count += 1
                        if not accepted_count:
                            raise ValueError("Signature archive contains no usable signature files: %s" % sig_url)
                        if cache is not None and sha is not None:
                            pending_caches.append((cache, sha, new_files))

            if stage_root is not None:
                self.validate_yara_rules(staged_dir)
                previous_dir = os.path.join(stage_root, 'previous')
                if os.path.exists(sig_dir):
                    os.replace(sig_dir, previous_dir)
                try:
                    os.replace(staged_dir, sig_dir)
                except Exception:
                    if os.path.exists(previous_dir):
                        try:
                            os.replace(previous_dir, sig_dir)
                        except Exception:
                            preserve_stage = True
                            self.logger.log("ERROR", "Upgrader", "Restore signatures manually from %s" % previous_dir)
                    raise
                for cache, sha, files in pending_caches:
                    try:
                        with open(cache + '.manifest.json', 'w') as manifest_file:
                            json.dump({'sha': sha, 'files': files}, manifest_file, sort_keys=True)
                        with open(cache, 'w') as cache_file:
                            cache_file.write(sha)
                    except OSError:
                        self.logger.log("NOTICE", "Upgrader", "Could not save the signature update cache: %s" % cache)

        except Exception as error:
            if self.debug:
                traceback.print_exc()
            self.logger.log("ERROR", "Upgrader", "Signature update failed; existing signatures were kept: %s" % error)
            return False
        finally:
            if stage_root is not None and not preserve_stage:
                shutil.rmtree(stage_root, ignore_errors=True)
        return True


    def update_loki(self):
        try:

            # Downloading the info for latest release
            try:
                self.logger.log("INFO", "Upgrader", "Checking location of latest release %s ..." % self.UPDATE_URL_LOKI)
                response_info = urlopen(self.UPDATE_URL_LOKI)
                data = json.load(response_info)
                # Get download URL
                zip_url = data['assets'][0]['browser_download_url']
                self.logger.log("INFO", "Upgrader", "Downloading latest release %s ..." % zip_url)
                response_zip = urlopen(zip_url)
            except Exception:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Upgrader", "Error downloading the AsterScan release - check the release and Internet connection")
                sys.exit(1)

            # Read ZIP file
            try:
                zipUpdate = zipfile.ZipFile(io.BytesIO(response_zip.read()))
                for zipFilePath in zipUpdate.namelist():
                    if zipFilePath.endswith("/") or "/config/" in zipFilePath or "/asterscan-updater.exe" in zipFilePath:
                        continue

                    source = zipUpdate.open(zipFilePath)
                    parts = zipFilePath.split("/")[1:]
                    if not parts:
                        continue
                    targetFile = os.path.abspath(os.path.join(self.application_path, *parts))
                    if os.path.commonpath([self.application_path, targetFile]) != self.application_path:
                        raise ValueError("Release archive contains a path outside the application directory")

                    self.logger.log("INFO", "Upgrader", "Extracting %s ..." %targetFile)

                    try:
                        # Create file if not present
                        if not os.path.exists(os.path.dirname(targetFile)):
                            if os.path.dirname(targetFile) != '':
                                os.makedirs(os.path.dirname(targetFile))
                    except Exception:
                        if self.debug:
                            self.logger.log("DEBUG", "Upgrader", "Cannot create dir name '%s'" % os.path.dirname(targetFile))
                            traceback.print_exc()

                    try:
                        # Create target file
                        target = open(targetFile, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                            if self.debug:
                                self.logger.log("DEBUG", "Upgrader", "Successfully extracted '%s'" % targetFile)
                        target.close()
                    except Exception:
                        self.logger.log("ERROR", "Upgrader", "Cannot extract '%s'" % targetFile)
                        if self.debug:
                            traceback.print_exc()

            except Exception:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Upgrader",
                                "Error while extracting the signature files from the download package")
                sys.exit(1)

        except Exception:
            if self.debug:
                traceback.print_exc()
            return False
        return True


def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and platform == "windows":
            # print "Trying to translate"
            # print application_path
            application_path = win32api.GetLongPathName(application_path)
        #if args.debug:
        #    logger.log("DEBUG", "Init", "Application Path: %s" % application_path)
        return application_path
    except Exception:
        print("Error while evaluation of application path")
        traceback.print_exc()


if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='AsterScan - Signature Updater')
    parser.add_argument('-l', help='Log file', metavar='log-file', default='asterscan-update.log')
    parser.add_argument('--sigsonly', action='store_true', help='Update signatures (the default)', default=False)
    parser.add_argument('--progonly', action='store_true', help='Update program files from an AsterScan release', default=False)
    parser.add_argument('--nolog', action='store_true', help='Don\'t write a local log file', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--clean', action='store_true', default=False, help='Clean up the signature directory and get '
                                                                            'a fresh set')
    parser.add_argument('--detached', action='store_true', default=False, help=argparse.SUPPRESS)

    args = parser.parse_args()
    if args.sigsonly and args.progonly:
        parser.error('--sigsonly and --progonly cannot be used together')

    # Computername
    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]

    # Logger
    logger = LokiLogger(args.nolog, args.l, t_hostname, '', '', False, False, False, args.debug, platform=platform, caller='upgrader')

    # Update AsterScan
    updater = LOKIUpdater(args.debug, logger, get_application_path())

    if args.progonly:
        logger.log("INFO", "Upgrader", "Updating AsterScan ...")
        updater.update_loki()
    else:
        logger.log("INFO", "Upgrader", "Updating Signatures ...")
        if not updater.update_signatures(args.clean):
            sys.exit(1)

    logger.log("INFO", "Upgrader", "Update complete")

    if args.detached:
        logger.log("INFO", "Upgrader", "Press any key to return ...")

    sys.exit(0)
