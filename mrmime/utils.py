import math
import random
import time
from cHaversine import haversine

import geopy
from requests.exceptions import ProxyError, ConnectionError, SSLError


# Returns destination coords given origin coords, distance (Ms) and bearing.
# This version is less precise and almost 1 order of magnitude faster than
# using geopy.
def fast_get_new_coords(origin, distance, bearing):
    R = 6371009  # IUGG mean earth radius in kilometers.

    oLat = math.radians(origin[0])
    oLon = math.radians(origin[1])
    b = math.radians(bearing)

    Lat = math.asin(
        math.sin(oLat) * math.cos(distance / R) +
        math.cos(oLat) * math.sin(distance / R) * math.cos(b))

    Lon = oLon + math.atan2(
        math.sin(bearing) * math.sin(distance / R) * math.cos(oLat),
        math.cos(distance / R) - math.sin(oLat) * math.sin(Lat))

    return math.degrees(Lat), math.degrees(Lon)


def jitter_location(lat, lng, maxMeters=5):
    origin = geopy.Point(lat, lng)
    bearing = random.randint(0, 360)
    distance = math.sqrt(random.random()) * (float(maxMeters))
    destination = fast_get_new_coords(origin, distance, bearing)
    return destination[0], destination[1]


def exception_caused_by_proxy_error(ex):
    if not ex.args:
        return False

    for arg in ex.args:
        if isinstance(arg, ProxyError) or isinstance(arg, SSLError) or isinstance(arg, ConnectionError):
            return True
        if isinstance(arg, Exception):
            return exception_caused_by_proxy_error(arg)

    return False


def get_spinnable_pokestops(gmo_response, step_location):
    forts = []
    cells = gmo_response['GET_MAP_OBJECTS'].map_cells
    for cell in cells:
        for fort in cell.forts:
            if fort.type == 1 and pokestop_spinnable(fort, step_location):
                forts.append(fort)
    return forts


# Check if Pokestop is spinnable and not on cooldown.
def pokestop_spinnable(fort, step_location):
    if not fort.enabled:
        return False

    spinning_radius = 38
    in_range = in_radius((fort.latitude, fort.longitude),
                         step_location, spinning_radius)
    now = time.time()
    pause_needed = fort.cooldown_complete_timestamp_ms / 1000 > now
    return in_range and not pause_needed


# Return True if distance between two locs is less than distance in meters.
def in_radius(loc1, loc2, radius):
    return distance(loc1, loc2) < radius


# Return approximate distance in meters.
def distance(pos1, pos2):
    return haversine((tuple(pos1))[0:2], (tuple(pos2))[0:2])


