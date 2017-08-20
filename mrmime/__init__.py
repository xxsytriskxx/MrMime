# Needed for download_remote_config_version request.
import json
import logging
import os

from pgoapi.hash_server import HashServer

log = logging.getLogger(__name__)

DEFAULT_CONFIG_FILE = 'mrmime_config.json'

GOMAN_HASHING_ENDPOINT = 'http://hash.goman.io/api/v137_1/hash'


_mr_mime_cfg = {
    # --- localization
    'player_locale': {                  # Default player locale
        'country': 'US',
        'language': 'en',
        'timezone': 'America/Denver'
    },
    # --- general
    'goman_hashing': False,             # Use GoMan hashing instead of Bossland
    'goman_hashing_rate_limit': None,   # Artificial rate limiting for GoMan hashing. Needs goman_hashing to be enabled.
    'goman_hashing_max_rpm_count': None,    # Artificial remaining RPM for GoMan hashing.
    'parallel_logins': True,            # Parallel logins increases number of requests.
    'exception_on_captcha': True,       # Raise CaptchaException if captcha detected
    'dump_bad_requests': False,
    # --- account login specific
    'login_retries': 3,                 # Number of login retries
    'login_delay': 6,                   # Delay between login retries
    'full_login_flow': True,            # Whether login flow requests should be performed or not
    'download_assets_and_items': True,  # Whether to perform download_asset_digest and download_item_templates requests at all
    # --- misc requests
    'scan_delay': 10,                   # Wait at least this long between 2 GMO requests
    # --- logging
    'debug_log': False,                 # If MrMime should output debug logging
    'log_file': None,                   # If given MrMime also logs into this file
    # --- PGPool support
    'pgpool_url': None,                 # URL of PGPool to manage account details
    'pgpool_system_id': None,           # System ID for PGPool - which system has the account in use
    'pgpool_auto_update': True,         # Whether MrMime updates PGPool account details automatically
    'pgpool_update_interval': 60        # Update account details in PGPool after this many seconds
}

# ---------------------------------------------------------------------------


def mrmime_pgpool_enabled():
    return _mr_mime_cfg['pgpool_url'] and _mr_mime_cfg['pgpool_system_id']


# ---------------------------------------------------------------------------

# Remember the original __init__ function because it gets replaced when using GoMan hashing with rate limit
__HashServer_init = HashServer.__init__


# New HashServer init function for GoMan hashing
def goman_hashing_hashserver_init(self, token):
    __HashServer_init(self, token)
    # Optionally configure artificial rate limit
    if _mr_mime_cfg['goman_hashing_rate_limit']:
        self.headers['X-RateLimit'] = _mr_mime_cfg['goman_hashing_rate_limit']
    # Optionally configure artificial max RPM count
    if _mr_mime_cfg['goman_hashing_max_rpm_count']:
        self.headers['X-MaxRPMCount'] = _mr_mime_cfg['goman_hashing_max_rpm_count']


def init_mr_mime(user_cfg=None, config_file=DEFAULT_CONFIG_FILE):
    if os.path.isfile(config_file):
        with open(config_file, 'r') as f:
            try:
                file_cfg = json.loads(f.read())
                log.info("Loading config from {}.".format(config_file))
                _mr_mime_cfg.update(file_cfg)
            except:
                log.error("Could not load config from {}."
                          " Is it proper JSON?".format(config_file))

    if user_cfg:
        log.info("Applying user configuration.")
        _mr_mime_cfg.update(user_cfg)

    if _mr_mime_cfg['debug_log'] is True:
        logging.getLogger('mrmime').setLevel(logging.DEBUG)

    if _mr_mime_cfg['log_file']:
        file_handler = logging.FileHandler(_mr_mime_cfg['log_file'])
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s [%(levelname)8s] %(message)s'))
        logging.getLogger('mrmime').addHandler(file_handler)

    if _mr_mime_cfg['goman_hashing']:
        # Inject GoMan hashing into pgoapi
        HashServer.__dict__['endpoint'] = GOMAN_HASHING_ENDPOINT
        HashServer.__init__ = goman_hashing_hashserver_init
        log.info("Using GoMan hashing instead of Bossland hashing.")
        if _mr_mime_cfg['goman_hashing_rate_limit']:
            log.info("Using artificial GoMan hashing rate limit of {} RPM.".format(
                _mr_mime_cfg['goman_hashing_rate_limit']))
        if _mr_mime_cfg['goman_hashing_max_rpm_count']:
            log.info("Using artificial GoMan hashing max RPM count of {} RPM.".format(
                _mr_mime_cfg['goman_hashing_max_rpm_count']))
