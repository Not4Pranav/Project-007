"""Static word lists and reference tables used to build believable profiles.

Deliberately dependency-free: a fixture generator that needs `pip install`
before it runs in CI is a fixture generator nobody keeps using.
"""

from __future__ import annotations

FIRST_NAMES: tuple[str, ...] = (
    "Aaron", "Ada", "Adrian", "Aisha", "Alina", "Amara", "Amir", "Ana", "Anders", "Anika",
    "Arjun", "Astrid", "Ayesha", "Beatriz", "Bruno", "Caleb", "Camila", "Carla", "Cedric", "Chen",
    "Chris", "Clara", "Dai", "Dalia", "Dante", "Daria", "David", "Dmitri", "Elena", "Eli",
    "Elif", "Emma", "Enzo", "Esme", "Farid", "Fatima", "Felix", "Finn", "Gabriel", "Greta",
    "Gustav", "Hana", "Hassan", "Hector", "Hugo", "Ida", "Ines", "Iris", "Ivan", "Jae",
    "Jakub", "Jamal", "Jana", "Javier", "Jonas", "Judy", "Kai", "Kamil", "Kira", "Lara",
    "Lars", "Lea", "Lena", "Leo", "Liam", "Lina", "Luca", "Lucia", "Lukas", "Maja",
    "Malik", "Marco", "Marta", "Maya", "Mei", "Milo", "Mira", "Nadia", "Nils", "Noor",
    "Nina", "Olga", "Omar", "Oskar", "Paloma", "Petra", "Pia", "Qadir", "Rafael", "Ravi",
    "Rowan", "Ryo", "Sana", "Sasha", "Selma", "Sofia", "Soren", "Talia", "Tariq", "Thea",
    "Thiago", "Tomas", "Tuana", "Umar", "Vera", "Viktor", "Wes", "Xiomara", "Yara", "Yusuf",
)

LAST_NAMES: tuple[str, ...] = (
    "Almeida", "Bauer", "Berg", "Bianchi", "Castillo", "Chowdhury", "Cruz", "Dahl", "Delgado", "Dubois",
    "Eklund", "Farah", "Ferrer", "Fischer", "Fontaine", "Garcia", "Grigoryan", "Haddad", "Hansen", "Horvat",
    "Ibarra", "Iversen", "Jensen", "Kaminski", "Kaur", "Keller", "Khoury", "Kowalski", "Kraus", "Laine",
    "Larsen", "Lindqvist", "Lopez", "Maier", "Mancini", "Marchetti", "Marin", "Mendoza", "Meyer", "Moller",
    "Moreau", "Novak", "Nunes", "Ohlsson", "Ortega", "Palmieri", "Pereira", "Petrov", "Picard", "Ramos",
    "Reyes", "Richter", "Rossi", "Ruiz", "Saito", "Salez", "Santos", "Schmidt", "Selim", "Silva",
    "Sorensen", "Stein", "Suzuki", "Tanaka", "Toure", "Varga", "Vidal", "Voss", "Weber", "Yilmaz",
    "Zhang", "Zielinski",
)

ADJECTIVES: tuple[str, ...] = (
    "amber", "arcane", "astral", "autumn", "azure", "brisk", "cinder", "cobalt", "cosmic", "crisp",
    "crimson", "copper", "dapper", "dusky", "eager", "electric", "ember", "fable", "fierce", "frosted",
    "gentle", "gilded", "glacial", "golden", "hollow", "icy", "indigo", "jagged", "lunar", "mellow",
    "merry", "misty", "molten", "nimble", "northern", "oceanic", "pale", "pocket", "quiet", "rapid",
    "rusty", "sable", "solar", "static", "sturdy", "sunny", "tidal", "tiny", "umber", "velvet",
    "vivid", "wandering", "wild", "winter", "zesty",
)

NOUNS: tuple[str, ...] = (
    "anchor", "atlas", "badger", "beacon", "bison", "bloom", "bolt", "compass", "copper", "cove",
    "crown", "delta", "drift", "echo", "falcon", "fern", "forge", "ferry", "fjord", "flare",
    "fox", "garden", "glade", "harbor", "heron", "islet", "jasmine", "jetty", "kestrel", "lantern",
    "maple", "marble", "meadow", "meteor", "moth", "nook", "orbit", "otter", "pebble", "penguin",
    "quartz", "quill", "ridge", "river", "sable", "sequoia", "sparrow", "spring", "summit", "thistle",
    "tiger", "tundra", "vireo", "walrus", "willow", "wolf",
)

# Free consumer providers. `free=True` means "a normal person could own this";
# the abuse detector only penalises the disposable bucket.
EMAIL_DOMAINS: tuple[tuple[str, int, bool], ...] = (
    ("gmail.com", 340, True),
    ("googlemail.com", 12, True),
    ("outlook.com", 130, True),
    ("hotmail.com", 95, True),
    ("live.com", 28, True),
    ("yahoo.com", 85, True),
    ("ymail.com", 6, True),
    ("icloud.com", 78, True),
    ("me.com", 10, True),
    ("protonmail.com", 26, True),
    ("proton.me", 14, True),
    ("pm.me", 4, True),
    ("aol.com", 12, True),
    ("mail.com", 9, True),
    ("web.de", 8, True),
    ("gmx.de", 7, True),
    ("gmx.net", 6, True),
    ("orange.fr", 5, True),
    ("libero.it", 4, True),
    ("tutanota.com", 5, True),
    ("fastmail.com", 3, True),
    ("zoho.com", 3, True),
    ("yandex.ru", 6, True),
    ("rambler.ru", 3, True),
    ("naver.com", 5, True),
    ("daum.net", 3, True),
    ("rediffmail.com", 2, True),
    # ---- throwaway providers, tracked so detection rules have something to find
    ("mailinator.com", 9, False),
    ("10minutemail.com", 7, False),
    ("temp-mail.org", 6, False),
    ("guerrillamail.com", 5, False),
    ("yopmail.com", 5, False),
    ("trashmail.com", 3, False),
    ("throwawaymail.com", 3, False),
    ("sharklasers.com", 2, False),
    ("getnada.com", 2, False),
    ("dispostable.com", 2, False),
)

DISPOSABLE_DOMAINS: frozenset[str] = frozenset(d for d, _w, free in EMAIL_DOMAINS if not free)

# (country, region, IANA-ish tz, utc offset hours, locale, population weight)
REGIONS: tuple[tuple[str, str, str, int, str, int], ...] = (
    ("IN", "Maharashtra", "Asia/Kolkata", 5.5, "en-IN", 210),
    ("US", "California", "America/Los_Angeles", -7, "en-US", 170),
    ("US", "New York", "America/New_York", -4, "en-US", 150),
    ("US", "Texas", "America/Chicago", -5, "en-US", 110),
    ("GB", "England", "Europe/London", 1, "en-GB", 95),
    ("DE", "Berlin", "Europe/Berlin", 2, "de-DE", 88),
    ("FR", "Ile-de-France", "Europe/Paris", 2, "fr-FR", 74),
    ("BR", "Sao Paulo", "America/Sao_Paulo", -3, "pt-BR", 92),
    ("MX", "Ciudad de Mexico", "America/Mexico_City", -6, "es-MX", 55),
    ("JP", "Tokyo", "Asia/Tokyo", 9, "ja-JP", 70),
    ("KR", "Seoul", "Asia/Seoul", 9, "ko-KR", 52),
    ("ID", "Jakarta", "Asia/Jakarta", 7, "id-ID", 58),
    ("NG", "Lagos", "Africa/Lagos", 1, "en-NG", 44),
    ("ZA", "Gauteng", "Africa/Johannesburg", 2, "en-ZA", 26),
    ("CA", "Ontario", "America/Toronto", -4, "en-CA", 40),
    ("AU", "New South Wales", "Australia/Sydney", 10, "en-AU", 34),
    ("NL", "North Holland", "Europe/Amsterdam", 2, "nl-NL", 28),
    ("ES", "Madrid", "Europe/Madrid", 2, "es-ES", 36),
    ("IT", "Lombardy", "Europe/Rome", 2, "it-IT", 34),
    ("PL", "Masovia", "Europe/Warsaw", 2, "pl-PL", 30),
    ("SE", "Stockholm", "Europe/Stockholm", 2, "sv-SE", 18),
    ("TR", "Istanbul", "Europe/Istanbul", 3, "tr-TR", 40),
    ("RU", "Moscow", "Europe/Moscow", 3, "ru-RU", 46),
    ("UA", "Kyiv", "Europe/Kyiv", 3, "uk-UA", 20),
    ("PK", "Punjab", "Asia/Karachi", 5, "en-PK", 30),
    ("PH", "Metro Manila", "Asia/Manila", 8, "en-PH", 26),
    ("VN", "Ho Chi Minh City", "Asia/Ho_Chi_Minh", 7, "vi-VN", 24),
    ("EG", "Cairo", "Africa/Cairo", 2, "ar-EG", 22),
    ("KE", "Nairobi", "Africa/Nairobi", 3, "sw-KE", 12),
    ("AR", "Buenos Aires", "America/Argentina/Buenos_Aires", -3, "es-AR", 28),
    ("CO", "Bogota", "America/Bogota", -5, "es-CO", 22),
    ("CN", "Shanghai", "Asia/Shanghai", 8, "zh-CN", 150),
    ("MY", "Kuala Lumpur", "Asia/Kuala_Lumpur", 8, "ms-MY", 14),
    ("NZ", "Auckland", "Pacific/Auckland", 12, "en-NZ", 7),
)

# (user agent string, relative weight) - desktop/mobile mix, plus one stale
# string reused by the injected automation cohort so rule R4 has signal.
USER_AGENTS: tuple[tuple[str, int], ...] = (
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36", 210),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", 120),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", 78),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0", 55),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/128.0.0.0 Safari/537.36", 60),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", 130),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36", 118),
    ("Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36", 70),
    ("Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1", 26),
    # automation cohort fingerprint
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/120.0.0.0 Safari/537.36", 1),
)

BOT_USER_AGENT = USER_AGENTS[-1][0]

DEVICE_CLASSES: tuple[tuple[str, int], ...] = (
    ("desktop", 48),
    ("mobile", 44),
    ("tablet", 8),
)

SOURCES: tuple[tuple[str, int], ...] = (
    ("organic", 46),
    ("referral", 27),
    ("ads", 14),
    ("campaign", 9),
    ("api", 4),
)

USERNAME_STYLES: tuple[tuple[str, int], ...] = (
    ("first.last.num", 26),        # aisha.bianchi41
    ("adjective_noun_num", 22),    # lunar_fjord_92
    ("handle", 20),                # quietmaple
    ("initial_last_num", 14),      # rrossi88
    ("nickname_repeat", 9),        # kai-kai-kai
    ("name_year", 9),              # marco2001
)

# Templates used by the injected automation cohort: same shape, digit suffix
# increments monotonically. Exactly what a username-template rule should catch.
BOT_USERNAME_TEMPLATES: tuple[str, ...] = (
    "guest{seq}", "user{seq}", "acct_{seq}", "member{seq}", "u{seq}x",
)

BIO_TEMPLATES: tuple[str, ...] = (
    "building things quietly",
    "coffee, trails, {noun}",
    "{adj} {noun} enthusiast",
    "here for the {noun} discourse",
    "pm by trade, {noun} by night",
    "learning {lang}",
    "{adj} since birth",
    "",
    "",
    "no bio",
    "dm me about {lang}",
    "collector of {noun}s",
)

LANGUAGES: tuple[str, ...] = (
    "Rust", "Elixir", "TypeScript", "Python", "Go", "Zig", "SQL", "Blender", "Kotlin", "Swift",
)
