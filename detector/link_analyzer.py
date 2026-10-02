"""Local heuristic checks on links. No network calls, so no message data leaves the device."""
import re
from urllib.parse import urlparse

URL_RE = re.compile(
    r"https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|in|org|net|xyz|top|biz|info)\b[^\s]*"
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "shorturl.at"}
SUSPICIOUS_TLDS = (".xyz", ".top", ".biz", ".info", ".gq", ".ml", ".cf")
SCAM_WORDS = {"kyc", "verify", "update", "login", "secure", "refund", "claim", "reward", "prize", "lucky"}
# brand -> its genuine domains (add more as you grow the list)
OFFICIAL = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "icici": {"icicibank.com"},
    "hdfc": {"hdfcbank.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
}


def extract_urls(text):
    """Find links and strip trailing punctuation such as a full stop after the link."""
    return [u.rstrip(".,;:!?)\"'") for u in URL_RE.findall(text)]


def _is_or_subdomain_of(domain, official):
    return domain == official or domain.endswith("." + official)


def analyze_link(url):
    reasons, score = [], 0
    full_url = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    domain = (urlparse(full_url).hostname or "").lower()   # hostname drops ports/credentials
    tokens = [t for t in re.split(r"[^a-z0-9]+", domain) if t]

    # 1. Shorteners: exact domain match (the old substring check flagged flipkart.com as "t.co")
    if any(_is_or_subdomain_of(domain, s) for s in SHORTENERS):
        score += 35
        reasons.append(f"Uses a URL shortener ({domain}), which hides the true destination.")

    # 2. Unusual endings
    if domain.endswith(SUSPICIOUS_TLDS):
        score += 30
        reasons.append(f"Uses an unusual domain ending ({domain}) often seen in scams.")

    # 3. Raw IP address or many subdomains
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain) or domain.count(".") > 3:
        score += 40
        reasons.append("Uses a raw IP address or an unusually long chain of subdomains.")

    # 4. Look-alike brand domains (old endswith check let fake-sbi.com pass as "sbi.com")
    for brand, genuine in OFFICIAL.items():
        mentions_brand = any(t.startswith(brand) for t in tokens)
        is_genuine = any(_is_or_subdomain_of(domain, g) for g in genuine)
        if mentions_brand and not is_genuine:
            score += 45
            reasons.append(f"Looks like it imitates {brand.upper()} but is not its official website.")
            break

    # 5. Scam-style words inside the domain itself
    if SCAM_WORDS & set(tokens):
        score += 25
        reasons.append("The web address contains words like 'verify', 'update' or 'KYC'.")

    return {"url": url, "domain": domain, "link_score": score, "link_reasons": reasons}


if __name__ == "__main__":
    for u in ["http://sbi-update-kyc.com/login", "https://www.flipkart.com", "http://fake-sbi.com", "bit.ly/abc"]:
        print(analyze_link(u))