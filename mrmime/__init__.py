# Needed for download_remote_config_version request.
import json
import logging
import os

from mrmime.goman import goman_enable_proxies, goman_enable_hashing

log = logging.getLogger(__name__)

DEFAULT_CONFIG_FILE = 'mrmime_config.json'

_mr_mime_cfg = {
    # --- localization
    'player_locale': {                  # Default player locale
        'country': 'US',
        'language': 'en',
        'timezone': 'America/Denver'
    },
    # --- general
    'goman_proxy_support': False,       # Patch PGoApi to be able to use GoMan proxies.
    'goman_hashing_rate_limit': None,   # Artificial rate limiting for GoMan hashing. Needs goman_hashing to be enabled.
    'goman_hashing_max_rpm_count': None,    # Artificial remaining RPM for GoMan hashing.
    'parallel_logins': True,            # Parallel logins increases number of requests.
    'exception_on_captcha': True,       # Raise CaptchaException if captcha detected
    'dump_bad_requests': False,         # Requests leading to BAD_REQUEST errors will be dumped to a file
    'jitter_gmo': True,                 # Perform location jitter on GET_MAP_OBJECTS requests
    # --- account login specific
    'login_retries': 3,                 # Number of login retries
    'login_delay': 6,                   # Delay between login retries
    'full_login_flow': True,            # Whether login flow requests should be performed or not
    'download_assets_and_items': True,  # Whether to perform download_asset_digest and download_item_templates requests at all
    'request_retry_delay': 5,           # Number of seconds to wait between request retries. Will be shorter if multiple hash keys and/or proxies are available.
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
    return bool(_mr_mime_cfg['pgpool_url'] and _mr_mime_cfg['pgpool_system_id'])


# ---------------------------------------------------------------------------


def init_mr_mime(user_cfg=None, config_file=DEFAULT_CONFIG_FILE):
    log.info("Configuring MrMime")

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

    if _mr_mime_cfg['goman_proxy_support']:
        goman_enable_proxies()

    goman_enable_hashing(_mr_mime_cfg)
