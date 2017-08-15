# Functions to deal with shadowbans / rareless scans

COMMON_POKEMON = [
    16,     # Pidgey
    19,     # Rattata
    23,     # Ekans
    27,     # Sandshrew
    29,     # Nidoran F
    32,     # Nidoran M
    41,     # Zubat
    43,     # Oddish
    46,     # Paras
    52,     # Meowth
    54,     # Psyduck
    60,     # Poliwag
    69,     # Bellsprout
    72,     # Tentacool
    74,     # Geodude
    77,     # Ponyta
    81,     # Magnemite
    98,     # Krabby
    118,    # Goldeen
    120,    # Staryu
    129,    # Magikarp
    161,    # Sentret
    165,    # Ledyba
    167,    # Spinarak
    177,    # Natu
    183,    # Marill
    187,    # Hoppip
    191,    # Sunkern
    194,    # Wooper
    198,    # Murkrow
    209,    # Snubbull
    218     # Slugma
]


def is_rareless_scan(gmo_response):
    for cell in gmo_response.map_cells:
        for p in cell.wild_pokemons:
            if p.pokemon_data.pokemon_id not in COMMON_POKEMON:
                return False
        for p in cell.nearby_pokemons:
            if p.pokemon_id not in COMMON_POKEMON:
                return False

    # No rare Pokemon found, so the scan was "rareless"
    return True
