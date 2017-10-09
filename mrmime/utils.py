import math
import random

import geopy
import geopy.distance
from requests.exceptions import ProxyError, ConnectionError, SSLError


def jitter_location(lat, lng, maxMeters=3):
    origin = geopy.Point(lat, lng)
    b = random.randint(0, 360)
    d = math.sqrt(random.random()) * (float(maxMeters) / 1000)
    destination = geopy.distance.distance(kilometers=d).destination(origin, b)
    return destination.latitude, destination.longitude


def exception_caused_by_proxy_error(ex):
    if not ex.args:
        return False

    for arg in ex.args:
        if isinstance(arg, ProxyError) or isinstance(arg, SSLError) or isinstance(arg, ConnectionError):
            return True
        if isinstance(arg, Exception):
            return exception_caused_by_proxy_error(arg)

    return False