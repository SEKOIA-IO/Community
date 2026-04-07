"""
Script to import the Intelligence Center indicators into a SPLUNK key-value store
"""
import logging
import json
import re
import sys
import time
from functools import lru_cache
from posixpath import join as urljoin
from typing import Dict, Optional, List, Tuple

import requests
import splunklib.client as client
from requests import RequestException


#################################
# Configuration                 #
# Change it to match your needs #
#################################

# Required configuration

# Intelligence center API key
APIKEY = ""
SPLUNK_COLLECTION_NAME = "3s_blacklist_sekoia_iocs"
# Details about splunk
SPLUNK_CONNECTION = {
    "host": "localhost",
    "port": 8089,
    "username": "admin",
    "password": "AZert1234",
    "scheme": "https",
    "app": "sekoia.io"
}

# Optional configuration

# FEED to use to get indicators
FEED_ID = "d6092c37-d8d7-45c3-8aff-c4dc26030608"

# File to use to store the cursors
CURSOR_FILE = "./cursors_db.txt"

# Request configuration, to add proxy info ...
REQUEST_EXTRA = {
    "verify": True,
    "proxies": {},
}
LOG_LEVEL = logging.INFO


def get_splunk_kv_collection():
    service = client.connect(**SPLUNK_CONNECTION)
    return service.kvstore[SPLUNK_COLLECTION_NAME]


class CursorStore(object):
    """
    Class to fetch and persist cursors
    """

    def __init__(self, file_path: str):
        self._file_path = file_path

    def get(self) -> Optional[str]:
        try:
            with open(self._file_path, "r") as f1:
                return f1.readlines()[-1]
        except FileNotFoundError:
            return None

    def set(self, cursor: str):
        with open(self._file_path, "a") as myfile:
            myfile.write(cursor + "\n")


class ICAPIHelper(object):
    """
    Helper to query the Intelligence Center
    """

    base_url = "https://api.sekoia.io/v2/inthreat/"

    @property
    def headers(self) -> Dict:
        return {"Authorization": f"Bearer {self._api_key}"}

    def __init__(self, api_key: str, request_extra: Dict = None):
        self._api_key = api_key
        self._request_extra = request_extra or {}
        self._cursor_store = CursorStore(CURSOR_FILE)
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.setLevel(LOG_LEVEL)  # Override default that is always to INFO

    def get_feed_url(self, feed: str, cursor: str = None) -> str:
        url = urljoin(
            self.base_url, "collections", feed, "objects?match[type]=indicator&limit=1500"
        )
        if cursor:
            url += f"&cursor={cursor}"
        return url

    def get_object_url(self, object_id: str) -> str:
        return urljoin(self.base_url, "objects", object_id)

    def iterate_feed(self, feed: str = "d6092c37-d8d7-45c3-8aff-c4dc26030608"):
        """
        Iterate of the given feed
        """
        cursor = self._cursor_store.get()
        count = 0
        self._logger.info(f"Starting with cursor {cursor}")
        while True:
            url = self.get_feed_url(feed, cursor)
            data = self._send_request(url)

            cursor = data["next_cursor"]
            self._cursor_store.set(cursor)

            if not data["items"]:
                self._logger.info(f"No more indicators to retrieve. Total: {count}")
                return
            count += len(data["items"])
            yield from data["items"]
            if count % 12000 == 0:
                self._logger.info(f"Processed {count} indicators")

    @lru_cache(maxsize=128)
    def get_object(self, object_id):
        """
        Get the given object from the intelligence center
        """
        self._logger.info(f"Fetching {object_id}")
        url = self.get_object_url(object_id)
        return self._send_request(url)["data"]

    def _send_request(self, url) -> Dict:
        try:
            start = time.time()
            self._logger.debug(f"Requesting {url}")
            response = requests.get(url, headers=self.headers, **self._request_extra)
            response.raise_for_status()
            self._logger.debug(f"Request took {time.time()-start} seconds")
            return response.json()
        except RequestException as ex:
            if ex.response and ex.response.status_code in [500, 504]:
                self._logger.error(f"Server returned {ex.response.status_code}, retrying")
                time.sleep(1)
                return self._send_request(url)
            raise


class IndicatorSerializer(object):
    """
    Class to serialize IC indicators into multiple SPLUNK collection entries.
    """

    domain_regex = re.compile(r"domain-name:value\s?=\s?'([^']*)'")
    url_regex = re.compile(r"url:value\s?=\s?'([^']*)'")
    ipv4_regex = re.compile(r"ipv4-addr:value\s?=\s?'([^']*)'")
    ipv6_regex = re.compile(r"ipv6-addr:value\s?=\s?'([^']*)'")
    sha1_regex = re.compile(r"file:hashes.'SHA-1'\s?=\s?'([^']*)'")
    sha256_regex = re.compile(r"file:hashes.'SHA-256'\s?=\s?'([^']*)'")
    sha512_regex = re.compile(r"file:hashes.'SHA-512'\s?=\s?'([^']*)'")
    md5_regex = re.compile(r"file:hashes.MD5\s?=\s?'([^']*)'")
    hash_regex = re.compile("file:hashes\[\*\]\s?=\s?'([^']*)'")

    def __init__(self, api_helper: ICAPIHelper):
        self._helper = api_helper

    def serialize(self, indicator: Dict) -> List[Dict]:
        base = {
            "added_by": "script",
            "source": "sekoia.io",
            "intelligence_center_id": indicator["id"],
            "created": indicator["created"],
            "valid_until": indicator.get("valid_until", "-"),
            "sources": self.get_source_names(indicator),
            "cyber_kill_chain": self.get_phase_name(indicator, "lockheed-martin-cyber-kill-chain"),
            "mitre_attack_phase": self.get_phase_name(indicator, "mitre-attack"),
            "threat": indicator["name"],
        }

        res = []
        for ioc_type, value in self.extract_pattern(indicator["pattern"]):
            ioc = base.copy()
            ioc["_key"] = value
            ioc["ioc_type"] = ioc_type
            ioc["ioc"] = value
            res.append(ioc)

        return res

    @staticmethod
    def get_phase_name(indicator: Dict, kill_chain: str) -> str:
        for phase in indicator.get("kill_chain_phases", []):
            if phase["kill_chain_name"] == kill_chain:
                return phase["phase_name"]
        return "-"

    def get_source_names(self, indicator: Dict):
        source_names = [
            self._helper.get_object(ref)["name"]
            for ref in indicator.get("x_inthreat_sources_refs", [])
        ]
        return ", ".join(source_names)

    def extract_pattern(self, pattern: str) -> List[Tuple[str, str]]:
        if " and " in pattern.lower():
            # Can't handle this kind of pattern
            return []

        res = [("domain", domain) for domain in self.domain_regex.findall(pattern)]
        res += [("url", url) for url in self.url_regex.findall(pattern)]
        res += [("ip", ip) for ip in self.ipv4_regex.findall(pattern)]
        res += [("ip", ip) for ip in self.ipv6_regex.findall(pattern)]
        res += [("sha256", sha) for sha in self.sha256_regex.findall(pattern)]
        res += [("sha512", sha) for sha in self.sha512_regex.findall(pattern)]
        res += [("sha1", sha) for sha in self.sha1_regex.findall(pattern)]
        res += [("md5", md5) for md5 in self.md5_regex.findall(pattern)]

        algorithms_by_length = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
        for h in self.hash_regex.findall(pattern):
            if len(h) in algorithms_by_length:
                res.append((algorithms_by_length[len(h)], h))

        return res


def main(api_key: str, feed: str, request_extra: Dict):
    logger = logging.getLogger("main")
    collection = get_splunk_kv_collection()
    api_helper = ICAPIHelper(api_key, request_extra=request_extra)
    serializer = IndicatorSerializer(api_helper)
    for indicator in api_helper.iterate_feed(feed):
        iocs = serializer.serialize(indicator)
        if not iocs:
            logger.info(f"No IOC extracted from {indicator['pattern']}")
            continue
        for ioc in iocs:
            dumped = json.dumps(ioc)
            collection.data.insert(dumped)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if not APIKEY:
        logging.error("API_KEY must be set, exiting")
        sys.exit(1)
    main(APIKEY, FEED_ID, REQUEST_EXTRA)
