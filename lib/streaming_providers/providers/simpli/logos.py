# streaming_providers/providers/simpli/logos.py
"""
simpliTV channel names and logos.

The channel-tile endpoint only yields a codename, so display names and
logos are derived locally. Ported from the existing addon's
channelname() / logomapper() so behaviour is identical, then extended
for the codenames observed in the browser capture.

Lookup order:

  1. _CODENAME_ALIASES -- explicit codename -> display-name table for
     the codenames whose derivation does not match the spelling used
     as a LOGO_MAP key.
  2. channel_name_from_codename -- general derivation (dashes to
     spaces, uppercase, strip trailing HD/FHD).
  3. LOGO_MAP -- display name -> logo URL.
  4. PROVIDER_LOGO fallback.
"""

from .constants import SimpliTVDefaults


# Codenames whose local derivation does not match the display name
# used as a LOGO_MAP key. Anything not in this table falls back to
# channel_name_from_codename().
_CODENAME_ALIASES = {
    "atvhd": "ATV",
    "atv-ii-fhd": "ATV II",
    "atv-2": "ATV 2",
    "n-tvhd": "N TV",
    "tele-5-hd": "TELE 5",
    "puls4austriahd": "PULS4",
    "puls24hd": "PULS24",
    "puls24": "PULS24",
    "pu4": "PU4",
    "prosiebenaustriahd": "PROSIEBEN AUSTRIA",
    "sat1austriahd": "SAT.1 AUSTRIA",
    "sat1goldaustriahd": "SAT.1 GOLD AUSTRIA",
    "rtlaustriahd": "RTL AUSTRIA",
    "rtlzweiaustriahd": "RTL ZWEI AUSTRIA",
    "rtlup-austria-hd": "RTLUP AUSTRIA",
    "rtl-crime-hd": "RTL CRIME",
    "rtl-living-hd": "RTL LIVING",
    "rtl-passion-hd": "RTL PASSION",
    "voxaustriahd": "VOX AUSTRIA",
    "kabeleinsaustriahd": "KABEL EINS AUSTRIA",
    "kabeleinsdokuhd": "KABELEINS DOKU",
    "prosiebenmaxxaustriahd": "PROSIEBEN MAXX AUSTRIA",
    "sixxaustriahd": "SIXX AUSTRIA",
    "nitro-austria-hd": "NITRO AUSTRIA",
    "dmaxaustriahd": "DMAX AUSTRIA",
    "tlcaustriahd": "TLC AUSTRIA",
    "geo-television-hd": "GEO TELEVISION",
    "hgtv-hd": "HGTV",
    "servustv-austria": "SERVUS TV AUSTRIA",
    "orf-sport-plus": "ORF SPORT PLUS",
    "orf-iii": "ORF III",
    "orf2-europe": "ORF 2 EUROPE",
    "orf1": "ORF 1",
    "orf2": "ORF 2",
    "orf2no": "ORF 2 NO",
    "orf2oo": "ORF 2 OOE",
    "orf2st": "ORF 2 STEIERMARK",
    "orf2t": "ORF 2 TIROL",
    "orf2b": "ORF 2 BURGENLAND",
    "orf2k": "ORF 2 KAERNTEN",
    "orf2s": "ORF 2 SALZBURG",
    "orf2v": "ORF 2 VORARLBERG",
    "orf-kids": "ORF KIDS",
    "zdf-hd": "ZDF",
    "zdfneo": "ZDF NEO",
    "zdfinfo-hd": "ZDF INFO",
    "ard-hd": "ARD",
    "ard-alpha-hd": "ARD ALPHA",
    "arte": "ARTE",
    "3sat": "3SAT",
    "kika-hd": "KIKA",
    "phoenix": "PHOENIX",
    "one": "ONE",
    "tagesschau-24-hd": "TAGESSCHAU 24",
    "hr-fernsehen-hd": "HR FERNSEHEN",
    "mdr-sachsen-hd": "MDR SACHSEN",
    "ndr": "NDR",
    "rbb-berlin-hd": "RBB BERLIN",
    "radio-bremen-hd": "RADIO BREMEN",
    "sr-fernsehen-hd": "SR FERNSEHEN",
    "swr-bw-hd": "SWR BW",
    "wdr-koeln-hd": "WDR KOELN",
    "br-hd": "BFS",
    "cnn": "CNN",
    "welt": "WELT",
    "euronews-german-sd": "EURONEWS ENGLISH",
    "al-jazeera-english-hd": "AL JAZEERA ENGLISH",
    "bloomberg-europe": "BLOOMBERG EUROPE",
    "tvp-world": "TVP WORLD",
    "nickelodeon": "NICKELODEON",
    "ric": "RIC",
    "ric-today": "RIC TODAY",
    "fix-und-foxi": "FIX UND FOXI",
    "superrtl-austria-hd": "SUPERRTL AUSTRIA",
    "k-tv": "K-T-V",
    "kronehit-tv": "KRONEHIT TV",
    "schau-tv": "SCHAU TV",
    "r9-oesterreich-hd": "R9 OESTERREICH",
    "sonnenklartv-hd": "SONNENKLARTV",
    "lt1-hd": "LT1",
    "tv1-ooe": "TV1 OOE",
    "laendletv": "LAENDLETV",
    "tiroltv": "TIROLTV",
    "dorftv": "DORFTV",
    "n1-noe-tv": "N1 NOE TV",
    "w24": "W24",
    "kt1": "KT1",
    "myzentv": "MYZENTV",
    "museum-tv": "MUSEUM TV",
    "kaminfeuer": "KAMINFEUER",
    "shoplc": "SHOP LC",
    "pegasus-hls": "PEGASUS HLS",
    "motorvision": "MOTORVISION",
    "more-than-sports": "MORE THAN SPORTS",
    "wedotv": "WEDOTV",
    "wedo-sports": "WEDO SPORTS",
    "wedo-big-stories": "WEDO BIG STORIES",
    "wedo-true-stories": "WEDO TRUE STORIES",
    "bibeltv-hd": "BIBELTV",
    "hopetvhd": "HOPETV",
    "kronehit-tv": "KRONEHIT TV",
    "schlager-deluxe": "SCHLAGER DELUXE",
    "melodietv": "MELODIETV",
    "deutsches-musikfernsehen": "DEUTSCHES MUSIKFERNSEHEN",
    "mtvaustriahd": "MTV AUSTRIA",
    "deluxemusicaustriahd": "DELUXEMUSIC AUSTRIA",
    "starbaradies-tv": "STARPARADISES TV",
    "lilo-tv": "LILO TV",
    "playboy-tv": "PLAYBOY TV",
    "hustler-tv": "HUSTLER TV",
    "dorcel-tv": "DORCEL TV",
    "radio-bremen-hd": "RADIO BREMEN",
    "ard-alpha-hd": "ARD ALPHA",
    "bfs": "BFS",
    "mtvaustriahd": "MTV AUSTRIA",
    "k-tv": "K-TV",
    "k-tv": "K-T-V",
}


LOGO_MAP = {
    # ------------------------------------------------------------------
    # Original addon entries, preserved verbatim.
    # ------------------------------------------------------------------
    "ORF1": "https://files.app.simplitv.at/files/orf1-hd-bunt.png",
    "ORF2NO": "https://files.app.simplitv.at/files/orf-no-e-hd-bunt.png",
    "ATV": "https://files.app.simplitv.at/files/atv-hd-bunt.png",
    "PULS4AUSTRIA": "https://files.app.simplitv.at/files/puls4-hd-bunt.png",
    "PU4": "https://files.app.simplitv.at/files/puls4-hd-bunt.png",
    "SERVUSTV AUSTRIA": "https://files.app.simplitv.at/files/servustv-hd-bunt.png",
    "ORF III": "https://files.app.simplitv.at/files/orf3-hd-bunt.png",
    "ATV 2": "https://files.app.simplitv.at/files/atv2-bunt.png",
    "OE24TV": "https://files.app.simplitv.at/files/oe24-tv-bunt.png",
    "PULS24": "https://files.app.simplitv.at/files/puls24-bunt.png",
    "PROSIEBENAUSTRIA": "https://files.app.simplitv.at/files/pro7-hd-bunt.png",
    "SAT1AUSTRIA": "https://files.app.simplitv.at/files/sat1-hd-bunt.png",
    "RTLAUSTRIA": "https://files.app.simplitv.at/files/rtl-austria-hd-bunt.png",
    "VOXAUSTRIA": "https://files.app.simplitv.at/files/vox-hd-bunt.png",
    "ZDF": "https://files.app.simplitv.at/files/zdf-hd-bunt.png",
    "ARD": "https://files.app.simplitv.at/files/ard-hd-bunt.png",
    "KABELEINSAUSTRIA": "https://files.app.simplitv.at/files/kabel1-hd-austria-bunt.png",
    "SAT1GOLDAUSTRIA": "https://files.app.simplitv.at/files/sat1-gold-hd-bunt.png",
    "3SAT": "https://files.app.simplitv.at/files/3sat-hd-bunt.png",
    "SIXXAUSTRIA": "https://files.app.simplitv.at/files/sixx-austria-hd-bunt.png",
    "PROSIEBENMAXXAUSTRIA": "https://files.app.simplitv.at/files/pro7-maxx-austria-bunt.png",
    "N TV": "https://files.app.simplitv.at/files/ntv-hd-bunt.png",
    "RTLZWEIAUSTRIA": "https://files.app.simplitv.at/files/rtl-zwei-hd-bunt.png",
    "ZDFNEO": "https://files.app.simplitv.at/files/zdf-neo-hd-bunt.png",
    "ZDFINFO": "https://files.app.simplitv.at/files/zdf-info-hd-bunt.png",
    "RTLUP AUSTRIA": "https://files.app.simplitv.at/files/rtluphd-kopie.png",
    "BFS": "https://files.app.simplitv.at/files/br-hd-bunt.png",
    "NITRO AUSTRIA": "https://files.app.simplitv.at/files/nitro-logo-hd.png",
    "TELE 5": "https://files.app.simplitv.at/files/tele-5-bunt.png",
    "COMEDY CENTRAL": "https://files.app.simplitv.at/files/comedy-central-austria-bunt.png",
    "ORF SPORT PLUS": "https://files.app.simplitv.at/files/orf-sport-plus-hd-bunt.png",
    "EUROSPORT1AUSTRIA": "https://files.app.simplitv.at/files/eurosport-1-hd-bunt.png",
    "SPORT1": "https://files.app.simplitv.at/files/sport1-hd-bunt.png",
    "LAOLA1TV": "https://files.app.simplitv.at/files/laola1-logo-rgb.jpg",
    "K19": "https://files.app.simplitv.at/files/element-1k19-logo.png",
    "ARTE": "https://files.app.simplitv.at/files/arte-hd-bunt.png",
    "TLCAUSTRIA": "https://files.app.simplitv.at/files/tlc-hd-bunt.png",
    "KABELEINSDOKU": "https://files.app.simplitv.at/files/kabel1-doku-austria-bunt.png",
    "DMAXAUSTRIA": "https://files.app.simplitv.at/files/dmax-hd-bunt.png",
    "PHOENIX": "https://files.app.simplitv.at/files/phoenix-bunt.png",
    "N24 DOKU": "https://files.app.simplitv.at/files/078-n24doku-1024x218.png",
    "SCHAU TV": "https://files.app.simplitv.at/files/kurier-tv-logo-cmyk-b.png",
    "KRONETV": "https://files.app.simplitv.at/files/kronetv-bunt.png",
    "R9 OESTERREICH": "https://files.app.simplitv.at/files/logor9.png",
    "WELT": "https://files.app.simplitv.at/files/welt-bunt.png",
    "TAGESSCHAU 24": "https://files.app.simplitv.at/files/069-tagesschau24hd-1024x208.png",
    "BILD TV": "https://files.app.simplitv.at/files/bild-tv-logo-august-2021.png",
    "CNN": "https://files.app.simplitv.at/files/cnn-bunt.png",
    "EURONEWS ENGLISH": "https://files.app.simplitv.at/files/logo-euronews-white-on-neon-rgb-kopie.png",
    "AL JAZEERA ENGLISH": "https://files.app.simplitv.at/files/aje-logo-rgb.png",
    "BLOOMBERG EUROPE": "https://files.app.simplitv.at/files/075-bloomberg-921x248.png",
    "TVP WORLD": "https://files.app.simplitv.at/files/tvp-world-logo-2022.jpg",
    "SUPERRTL AUSTRIA": "https://files.app.simplitv.at/files/super-rtl-hd-logo-orange.png",
    "KIKA": "https://files.app.simplitv.at/files/kika-hd-bunt.png",
    "NICKELODEON": "https://files.app.simplitv.at/files/nick-austria-bunt.png",
    "RIC": "https://files.app.simplitv.at/files/ric-bunt.png",
    "FIX UND FOXI": "https://files.app.simplitv.at/files/fix-foxi-bunt.png",
    "ORF2": "https://files.app.simplitv.at/files/orf2-hd-bunt.png",
    "ORF2OO": "https://files.app.simplitv.at/files/orf-oo-e-hd-bunt.png",
    "ORF2ST": "https://files.app.simplitv.at/files/orf-steiermark-hd-bunt.png",
    "ORF2T": "https://files.app.simplitv.at/files/orf-tirol-hd-bunt.png",
    "ORF2B": "https://files.app.simplitv.at/files/orf-hd-burgenland-bunt.png",
    "ORF2K": "https://files.app.simplitv.at/files/orf-hd-ka-ernten-bunt.png",
    "ORF2S": "https://files.app.simplitv.at/files/orf-salzburg-hd-bunt.png",
    "ORF2V": "https://files.app.simplitv.at/files/orf-vorarlberg-hd-bunt.png",
    "KT1": "https://files.app.simplitv.at/files/kt1.png",
    "WNTV": "https://files.app.simplitv.at/files/wntv-ihr-privatfernsehen-logo-1801150443.jpg",
    "W24": "https://files.app.simplitv.at/files/100-w24.png",
    "N1 NOE TV": "https://files.app.simplitv.at/files/senderlogo-oesterreichprogramm-n1.png",
    "LT1": "https://files.app.simplitv.at/files/lt1-logo-neu.png",
    "TV1 OOE": "https://files.app.simplitv.at/files/rz-logo-tv1-pos-rgb.jpg",
    "TIROLTV": "https://files.app.simplitv.at/files/tiroltv.png",
    "LAENDLETV": "https://files.app.simplitv.at/files/landletv-s-auf-w.png",
    "DORFTV": "https://files.app.simplitv.at/files/dorftv-kopie-2.png",
    "ONE": "https://files.app.simplitv.at/files/one-hd-bunt.png",
    "SWR BW": "https://files.app.simplitv.at/files/062-swtbwhd-366x71.png",
    "SR FERNSEHEN": "https://files.app.simplitv.at/files/067-srfernsehenhd-1024x627.png",
    "NDR": "https://files.app.simplitv.at/files/ndr-hd-bunt.png",
    "WDR KOELN": "https://files.app.simplitv.at/files/063-wdrhd-1024x341.png",
    "MDR SACHSEN": "https://files.app.simplitv.at/files/mdr-rgb.png",
    "HR FERNSEHEN": "https://files.app.simplitv.at/files/065-hr-fernsehenhd-170x75.png",
    "RBB BERLIN": "https://files.app.simplitv.at/files/rbb-rgb.png",
    "ARD ALPHA": "https://files.app.simplitv.at/files/ardaplha-rgb.png",
    "RADIO BREMEN": "https://files.app.simplitv.at/files/radio-bremen-rgb.jpg",
    "OE3 VISUAL RADIO": "https://files.app.simplitv.at/files/oe3-logo.png",
    "MTVAUSTRIA": "https://files.app.simplitv.at/files/mtv-hd-bunt.png",
    "DELUXEMUSICAUSTRIA": "https://files.app.simplitv.at/files/deluxe-music-hd-bunt.png",
    "MELODIETV": "https://files.app.simplitv.at/files/093-melodietv-573x538.png",
    "SCHLAGER DELUXE": "https://files.app.simplitv.at/files/schlager-deluxe-logo.png",
    "DEUTSCHES MUSIKFERNSEHEN": "https://files.app.simplitv.at/files/deutsches-musik-fernsehen-infarbe.jpg",
    "VOLKSMUSIK TV": "https://files.app.simplitv.at/files/911px-volksmusik-tv-logosvg.png",
    "MEI MUSI TV": "https://files.app.simplitv.at/files/mei-musi-tv.png",
    "STARPARADISES TV": "https://files.app.simplitv.at/files/starparadies.png",
    "LILO TV": "https://files.app.simplitv.at/files/lilo-color.png",
    "HGTV": "https://files.app.simplitv.at/files/hgtv-bunt.png",
    "ARCADIA TV": "https://files.app.simplitv.at/files/arcadiaworld.png",
    "SONNENKLARTV": "https://files.app.simplitv.at/files/sk-tv-clm-rgb.png",
    "BIBELTV": "https://files.app.simplitv.at/files/084-bibeltvhd-1024x198.png",
    "FASHION TV": "https://files.app.simplitv.at/files/fashiontv-logo-blue-vertical-1.png",
    "PLAYBOY TV": "https://files.app.simplitv.at/files/dorcel-2022-playboytveurope-logo-noir-transparent.png",
    "HUSTLER TV": "https://files.app.simplitv.at/files/hustlertv-light.jpg",
    "DORCEL TV": "https://files.app.simplitv.at/files/2022-dorceltv-black-rvb.jpg",

    # ------------------------------------------------------------------
    # Extensions from the browser capture.
    # Names here are the alias-table targets; do not rename without
    # updating _CODENAME_ALIASES.
    # ------------------------------------------------------------------
    "ATV II": "https://files.app.simplitv.at/files/atv2-bunt.png",
    "PULS4": "https://files.app.simplitv.at/files/puls4-hd-bunt.png",
    "PROSIEBEN AUSTRIA": "https://files.app.simplitv.at/files/pro7-hd-bunt.png",
    "SAT.1 AUSTRIA": "https://files.app.simplitv.at/files/sat1-hd-bunt.png",
    "SAT.1 GOLD AUSTRIA": "https://files.app.simplitv.at/files/sat1-gold-hd-bunt.png",
    "RTL AUSTRIA": "https://files.app.simplitv.at/files/rtl-austria-hd-bunt.png",
    "RTL ZWEI AUSTRIA": "https://files.app.simplitv.at/files/rtl-zwei-hd-bunt.png",
    "RTLUP AUSTRIA": "https://files.app.simplitv.at/files/rtluphd-kopie.png",
    "RTL CRIME": "https://files.app.simplitv.at/files/rtl-crime-hd-bunt.png",
    "RTL LIVING": "https://files.app.simplitv.at/files/rtl-living-hd-bunt.png",
    "RTL PASSION": "https://files.app.simplitv.at/files/rtl-passion-hd-bunt.png",
    "VOX AUSTRIA": "https://files.app.simplitv.at/files/vox-hd-bunt.png",
    "KABEL EINS AUSTRIA": "https://files.app.simplitv.at/files/kabel1-hd-austria-bunt.png",
    "KABELEINS DOKU": "https://files.app.simplitv.at/files/kabel1-doku-austria-bunt.png",
    "PROSIEBEN MAXX AUSTRIA": "https://files.app.simplitv.at/files/pro7-maxx-austria-bunt.png",
    "SIXX AUSTRIA": "https://files.app.simplitv.at/files/sixx-austria-hd-bunt.png",
    "DMAX AUSTRIA": "https://files.app.simplitv.at/files/dmax-hd-bunt.png",
    "TLC AUSTRIA": "https://files.app.simplitv.at/files/tlc-hd-bunt.png",
    "GEO TELEVISION": "https://files.app.simplitv.at/files/geo-television-hd-bunt.png",
    "ZDF NEO": "https://files.app.simplitv.at/files/zdf-neo-hd-bunt.png",
    "ZDF INFO": "https://files.app.simplitv.at/files/zdf-info-hd-bunt.png",
    "ORF 1": "https://files.app.simplitv.at/files/orf1-hd-bunt.png",
    "ORF 2": "https://files.app.simplitv.at/files/orf2-hd-bunt.png",
    "ORF 2 NO": "https://files.app.simplitv.at/files/orf-no-e-hd-bunt.png",
    "ORF 2 OOE": "https://files.app.simplitv.at/files/orf-oo-e-hd-bunt.png",
    "ORF 2 STEIERMARK": "https://files.app.simplitv.at/files/orf-steiermark-hd-bunt.png",
    "ORF 2 TIROL": "https://files.app.simplitv.at/files/orf-tirol-hd-bunt.png",
    "ORF 2 BURGENLAND": "https://files.app.simplitv.at/files/orf-hd-burgenland-bunt.png",
    "ORF 2 KAERNTEN": "https://files.app.simplitv.at/files/orf-hd-ka-ernten-bunt.png",
    "ORF 2 SALZBURG": "https://files.app.simplitv.at/files/orf-salzburg-hd-bunt.png",
    "ORF 2 VORARLBERG": "https://files.app.simplitv.at/files/orf-vorarlberg-hd-bunt.png",
    "ORF 2 EUROPE": "https://files.app.simplitv.at/files/orf2-europe-hd-bunt.png",
    "ORF KIDS": "https://files.app.simplitv.at/files/orf-kids-bunt.png",
    "RIC TODAY": "https://files.app.simplitv.at/files/ric-today-bunt.png",
    "MUSEUM TV": "https://files.app.simplitv.at/files/museum-tv-logo.png",
    "KAMINFEUER": "https://files.app.simplitv.at/files/kaminfeuer-bunt.png",
    "SHOP LC": "https://files.app.simplitv.at/files/shoplc-bunt.png",
    "PEGASUS HLS": "https://files.app.simplitv.at/files/pegasus-hls.png",
    "MOTORVISION": "https://files.app.simplitv.at/files/motorvision-hd-bunt.png",
    "MORE THAN SPORTS": "https://files.app.simplitv.at/files/more-than-sports-bunt.png",
    "WEDOTV": "https://files.app.simplitv.at/files/wedotv-bunt.png",
    "WEDO SPORTS": "https://files.app.simplitv.at/files/wedo-sports-bunt.png",
    "WEDO BIG STORIES": "https://files.app.simplitv.at/files/wedo-big-stories-bunt.png",
    "WEDO TRUE STORIES": "https://files.app.simplitv.at/files/wedo-true-stories-bunt.png",
    "HOPETV": "https://files.app.simplitv.at/files/hopetv-bunt.png",
    "KRONEHIT TV": "https://files.app.simplitv.at/files/kronehit-tv-logo.png",
    "MYZENTV": "https://files.app.simplitv.at/files/museum-tv-logo.png",
    "K-T-V": "https://files.app.simplitv.at/files/k-tv-bunt.png",
    "K-TV": "https://files.app.simplitv.at/files/k-tv-bunt.png",
    "DELUXEMUSIC AUSTRIA": "https://files.app.simplitv.at/files/deluxe-music-hd-bunt.png",
    "STARPARADISES TV": "https://files.app.simplitv.at/files/starparadies.png",
}


def channel_name_from_codename(codename: str) -> str:
    """
    Display name for a codename.

    Prefers the explicit alias table; otherwise normalises dashes and
    underscores to spaces, uppercases, and strips a trailing HD / FHD
    quality suffix.
    """
    if not codename:
        return ""

    lower = codename.lower()
    if lower in _CODENAME_ALIASES:
        return _CODENAME_ALIASES[lower]

    name = codename.replace("-", " ").replace("_", " ").upper()

    # Strip a trailing quality marker. FHD must be checked before HD.
    for suffix in (" FHD", "FHD", " HD", "HD"):
        if name.endswith(suffix) and len(name) > len(suffix):
            name = name[: -len(suffix)].rstrip()
            break

    # Collapse any double spaces left behind.
    while "  " in name:
        name = name.replace("  ", " ")

    return name


def logo_for_name(name: str) -> str:
    """Logo URL for a display name; provider logo when unknown."""
    return LOGO_MAP.get(name) or SimpliTVDefaults.PROVIDER_LOGO