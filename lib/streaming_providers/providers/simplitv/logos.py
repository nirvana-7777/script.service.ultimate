# streaming_providers/providers/simplitv/logos.py
"""
simpliTV channel names and logos.

The channel-tile endpoint only yields a codename, so display names and
logos are derived locally. Ported from the existing addon's
channelname() / logomapper() so behaviour is identical.
"""

from .constants import SimpliTVDefaults

LOGO_MAP = {
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
    "WDR KÖLN": "https://files.app.simplitv.at/files/063-wdrhd-1024x341.png",
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
}


def channel_name_from_codename(codename: str) -> str:
    """Display name for a codename (mirrors the addon's channelname())."""
    name = codename.replace("-", " ").upper()
    if name.endswith(" HD"):
        name = name[:-3]
    if name.endswith("HD"):
        name = name[:-2]
    return name


def logo_for_name(name: str) -> str:
    """Logo URL for a display name; provider logo when unknown."""
    return LOGO_MAP.get(name) or SimpliTVDefaults.PROVIDER_LOGO
