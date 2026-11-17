"""Reference lists used by the feature extractors and the rules.

Everything here is plain data so it can be reviewed (and argued about) without
reading any logic. Each list says WHY it exists and where the idea comes from.
"""
from __future__ import annotations

# --- Brands that phishing kits impersonate most often ----------------------------
# keyword -> domains the brand really uses. A keyword appearing in a URL whose
# host is NOT one of these domains is evidence of impersonation
# (e.g. paypal.com.secure-login.xyz). Picked from the brands that APWG and
# vendor reports list as most phished, plus Indian banks and apps because that
# is where this project's users are.
#
# Matching rules live in lexical.py: keywords of 6+ letters match anywhere in a
# token ("mypaypal"), 4-5 letters only at the start ("appleid"), and shorter
# keywords only as a whole token, so "pineapple" and "purchase" do not count
# as Apple or Chase.
_MICROSOFT = ("microsoft.com", "live.com", "office.com", "microsoftonline.com",
              "outlook.com", "office365.com", "microsoft365.com", "sharepoint.com",
              "onedrive.com", "msn.com", "bing.com", "azure.com", "windows.net",
              "skype.com", "xbox.com")
_GOOGLE = ("google.com", "gmail.com", "youtube.com", "googleusercontent.com",
           "googleapis.com", "gstatic.com", "google.co.in", "google.co.uk",
           "google.de", "google.ca", "google.com.au", "goo.gl", "g.co")
_META = ("facebook.com", "fb.com", "meta.com", "messenger.com", "fbcdn.net",
         "instagram.com", "whatsapp.com", "whatsapp.net", "wa.me")

BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "apple": ("apple.com", "icloud.com", "apple.co"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": _MICROSOFT,
    "office365": _MICROSOFT,
    "onedrive": _MICROSOFT,
    "google": _GOOGLE,
    "gmail": _GOOGLE,
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca",
               "amazon.co.jp", "amazon.fr", "amazon.it", "amazon.es", "amazon.com.au",
               "amazonaws.com", "primevideo.com", "amazon.jobs"),
    "netflix": ("netflix.com", "nflxext.com"),
    "facebook": _META,
    "instagram": _META,
    "whatsapp": _META,
    "linkedin": ("linkedin.com", "lnkd.in"),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com", "db.tt"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobelogin.com", "acrobat.com", "adobe.io"),
    "github": ("github.com", "githubusercontent.com", "githubassets.com"),
    "yahoo": ("yahoo.com", "yahoo.co.jp", "yimg.com"),
    "ebay": ("ebay.com", "ebay.co.uk", "ebay.in", "ebay.de"),
    "spotify": ("spotify.com",),
    "steamcommunity": ("steamcommunity.com", "steampowered.com"),
    "steampowered": ("steamcommunity.com", "steampowered.com"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "chase": ("chase.com", "jpmorganchase.com", "jpmorgan.com"),
    "wellsfargo": ("wellsfargo.com", "wf.com"),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "citibank": ("citi.com", "citibank.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk", "hsbc.co.in"),
    "barclays": ("barclays.co.uk", "barclays.com"),
    "americanexpress": ("americanexpress.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    # India. RBI asked banks to move to *.bank.in during 2025, so both the old
    # and the new domains are listed.
    "sbi": ("onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "sbi.bank.in"),
    "onlinesbi": ("onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "sbi.bank.in"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfcbank.bank.in", "hdfc.bank.in"),
    "icici": ("icicibank.com", "icici.bank.in"),
    "axisbank": ("axisbank.com", "axis.bank.in"),
    "kotak": ("kotak.com", "kotak.bank.in"),
    "paytm": ("paytm.com", "paytm.in"),
    "phonepe": ("phonepe.com",),
    "irctc": ("irctc.co.in", "irctc.com"),
    "flipkart": ("flipkart.com",),
    "airtel": ("airtel.in", "airtel.com"),
}

# Human-readable name for messages ("paypal" -> "PayPal").
BRAND_DISPLAY: dict[str, str] = {
    "paypal": "PayPal", "apple": "Apple", "icloud": "iCloud", "microsoft": "Microsoft",
    "office365": "Microsoft 365", "onedrive": "OneDrive", "google": "Google",
    "gmail": "Gmail", "amazon": "Amazon", "netflix": "Netflix", "facebook": "Facebook",
    "instagram": "Instagram", "whatsapp": "WhatsApp", "linkedin": "LinkedIn",
    "twitter": "Twitter/X", "dropbox": "Dropbox", "docusign": "DocuSign",
    "adobe": "Adobe", "github": "GitHub", "yahoo": "Yahoo", "ebay": "eBay",
    "spotify": "Spotify", "steamcommunity": "Steam", "steampowered": "Steam",
    "coinbase": "Coinbase", "binance": "Binance", "metamask": "MetaMask",
    "chase": "Chase", "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America",
    "citibank": "Citibank", "hsbc": "HSBC", "barclays": "Barclays",
    "americanexpress": "American Express", "dhl": "DHL", "fedex": "FedEx",
    "usps": "USPS", "sbi": "SBI", "onlinesbi": "SBI", "hdfc": "HDFC Bank",
    "icici": "ICICI Bank", "axisbank": "Axis Bank", "kotak": "Kotak", "paytm": "Paytm",
    "phonepe": "PhonePe", "irctc": "IRCTC", "flipkart": "Flipkart", "airtel": "Airtel",
}

# --- Well-known sites ---------------------------------------------------------
# Used ONLY to stop false positives on very popular sites (a long Google Docs
# link is not phishing). Every brand domain is included, plus popular sites.
# Hosts in USER_CONTENT_HOSTS below never get this benefit even when their
# parent domain is listed, because anyone can publish pages there.
KNOWN_GOOD_DOMAINS: frozenset[str] = frozenset(
    {d for domains in BRANDS.values() for d in domains}
    | {
        "wikipedia.org", "wikimedia.org", "stackoverflow.com", "stackexchange.com",
        "reddit.com", "quora.com", "medium.com", "nytimes.com", "bbc.co.uk", "bbc.com",
        "cnn.com", "theguardian.com", "reuters.com", "ndtv.com", "thehindu.com",
        "timesofindia.com", "indiatimes.com", "hindustantimes.com",
        "zoom.us", "slack.com", "notion.so", "atlassian.com", "gitlab.com",
        "npmjs.com", "pypi.org", "python.org", "mozilla.org", "cloudflare.com",
        "vercel.com", "netlify.com", "openai.com", "anthropic.com", "claude.ai",
        "twitch.tv", "tiktok.com", "pinterest.com", "imdb.com", "booking.com",
        "airbnb.com", "uber.com", "zomato.com", "swiggy.com", "myntra.com",
        "nptel.ac.in", "gov.in", "nic.in", "india.gov.in", "incometax.gov.in",
        "w3schools.com", "geeksforgeeks.org", "leetcode.com", "coursera.org",
        "udemy.com", "khanacademy.org", "kaggle.com", "huggingface.co",
    }
)

# --- Platforms where anyone can publish a page --------------------------------
# Free hosting and file-sharing hosts are heavily abused because they come with
# a trusted-looking domain and a free TLS certificate. Matching is by suffix:
# "abc.netlify.app" matches "netlify.app".
USER_CONTENT_HOSTS: tuple[str, ...] = (
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "web.app",
    "firebaseapp.com", "appspot.com", "blogspot.com", "github.io", "gitlab.io",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev",
    "herokuapp.com", "glitch.me", "repl.co", "replit.app", "replit.dev",
    "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com",
    "wordpress.com", "godaddysites.com", "square.site", "webflow.io",
    "myshopify.com", "carrd.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "ipfs.io", "dweb.link", "azurewebsites.net", "web.core.windows.net",
    "s3.amazonaws.com", "myqcloud.com", "sharepoint.com", "1drv.ms",
    "onedrive.live.com", "dropboxusercontent.com", "typedream.app", "framer.app",
)

# --- URL shorteners -------------------------------------------------------------
# A shortened link hides its destination until it is followed.
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly",
    "s.id", "v.gd", "bl.ink", "lnkd.in", "surl.li", "qrco.de", "shorturl.asia",
})

# --- TLDs that are disproportionately abused -----------------------------------
# From the Spamhaus "most abused TLDs" tables and Interisle's Phishing Landscape
# reports: cheap or free registration and little abuse handling. A TLD on this
# list is weak evidence on its own; plenty of honest sites use .xyz.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "buzz", "cyou", "rest",
    "sbs", "cfd", "bond", "click", "link", "support", "zip", "mov", "country",
    "kim", "gdn", "men", "loan", "win", "bid", "review", "date", "racing",
    "download", "stream", "quest", "lat", "monster", "work", "fit", "su",
})

# --- Words phishing URLs use to sound official ---------------------------------
# Starts from the classic list in Garera et al., "A Framework for Detection and
# Measurement of Phishing Attacks" (2007): secure, account, webscr, login,
# ebayisapi, signin, banking, confirm; extended with words seen in modern kits.
SUSPICIOUS_WORDS: tuple[str, ...] = (
    "login", "signin", "logon", "verify", "verification", "account", "update",
    "secure", "banking", "confirm", "password", "webscr", "ebayisapi", "wallet",
    "recover", "unlock", "suspend", "billing", "invoice", "authenticate",
    "validate", "kyc", "refund", "reward", "bonus", "prize", "claim",
)


def host_in(host: str, domains) -> bool:
    """True when host is one of `domains` or a subdomain of one.

    WHY suffix matching instead of comparing registrable domains: some brand
    domains (sbi.bank.in) sit under suffixes the bundled Public Suffix List
    does not know yet, and "mail.google.com" must count as google.com.
    """
    return any(host == d or host.endswith("." + d) for d in domains)


def matching_suffix(host: str, suffixes) -> str | None:
    """Return the first entry of `suffixes` that host equals or ends with."""
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None
