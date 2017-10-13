import logging

from pgoapi import PGoApi
from pgoapi.auth_ptc import AuthPtc
from pgoapi.hash_server import HashServer

log = logging.getLogger(__name__)

BOSSLAND_HASHING_ENDPOINT = HashServer.__dict__['endpoint']
GOMAN_HASHING_ENDPOINT = 'http://hash.goman.io' + BOSSLAND_HASHING_ENDPOINT[BOSSLAND_HASHING_ENDPOINT.find('/api/'):]

goman_rate_limit = None
goman_max_rpm_count = None

# Remember the original __init__ functions because it gets replaced when patching PgoApi for GoMan services
__HashServer_init = HashServer.__init__
__PGoApi_init = PGoApi.__init__
__AuthPtc_init = AuthPtc.__init__


# New HashServer init function for GoMan hashing
def goman_hashserver_init(self, token):
    __HashServer_init(self, token)

    # Patch hash server if using GoMan key
    if token.startswith('PH'):
        self.endpoint = GOMAN_HASHING_ENDPOINT

        # Optionally configure artificial rate limit
        if goman_rate_limit:
            self.headers['X-RateLimit'] = str(goman_rate_limit)

        # Optionally configure artificial max RPM count
        if goman_max_rpm_count:
            self.headers['X-MaxRPMCount'] = str(goman_max_rpm_count)


def pgoapi_init_noverify(self, provider=None, oauth2_refresh_token=None, username=None, password=None,
                         position_lat=None, position_lng=None, position_alt=None, proxy_config=None, device_info=None):
    __PGoApi_init(self, provider, oauth2_refresh_token, username, password, position_lat, position_lng, position_alt,
                  proxy_config, device_info)
    self._session.verify = False


def auth_ptc_init_noverify(self, username=None, password=None, user_agent=None, timeout=None, locale=None):
    __AuthPtc_init(self, username, password, user_agent, timeout, locale)
    self._session.verify = False


def goman_enable_hashing(cfg):
    global goman_rate_limit
    global goman_max_rpm_count

    log.info("Patching PGoApi to be able to use GoMan Hashing keys.")
    goman_rate_limit = cfg['goman_hashing_rate_limit']
    goman_max_rpm_count = cfg['goman_hashing_max_rpm_count']

    if goman_rate_limit:
        log.info("Using artificial GoMan hashing rate limit of {} RPM.".format(
            goman_rate_limit))
    if goman_max_rpm_count:
        log.info("Using artificial GoMan hashing max RPM count of {} RPM.".format(
            goman_max_rpm_count))

    # Replace constructor
    HashServer.__init__ = goman_hashserver_init


def goman_enable_proxies():
    log.info("Patching PGoApi to support GoMan proxies")
    PGoApi.__init__ = pgoapi_init_noverify
    AuthPtc.__init__ = auth_ptc_init_noverify
