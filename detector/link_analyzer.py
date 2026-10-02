import re
from urllib.parse import urlparse

def extract_urls(text):
    """Extracts URLs from message text using regular expressions."""
    url_pattern = r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|in|org|net|xyz|top|biz|info)[^\s]*'
    return re.findall(url_pattern, text)

def analyze_link(url):
    """
    Performs local heuristic analysis on a URL to detect red flags
    like shortened links, suspicious TLDs, and look-alike indicators.
    """
    reasons = []
    score = 0
    
    # Ensure URL has scheme for parsing
    if not url.startswith(('http://', 'https://')):
        full_url = 'http://' + url
    else:
        full_url = url
        
    parsed = urlparse(full_url)
    domain = parsed.netloc.lower()
    
    # 1. Shortened URL Check
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'shorturl.at']
    if any(short in domain for short in shorteners):
        score += 35
        reasons.append(f"Uses a URL shortener ({domain}), which hides the true destination.")
        
    # 2. Suspicious / Unusual Domain Endings
    suspicious_tlds = ['.xyz', '.top', '.biz', '.info', '.gq', '.ml', '.cf']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 30
        reasons.append(f"Uses an unusual domain extension ({domain}) commonly associated with scams.")
        
    # 3. Excessive Subdomains or IP-based URLs
    if domain.count('.') > 3 or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 40
        reasons.append("Contains an unusual IP address or excessive subdomains.")
        
    # 4. Brand Impersonation / Look-alike Heuristic (e.g., sbi-update-kyc)
    known_brands = ['sbi', 'icici', 'hdfc', 'paytm', 'axis', 'amazon', 'flipkart']
    for brand in known_brands:
        if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.co.in"):
            score += 45
            reasons.append(f"Impersonates a known brand ({brand}) on an unverified domain.")

    return {
        "url": url,
        "domain": domain,
        "link_score": score,
        "link_reasons": reasons
    }

if __name__ == "__main__":
    test_url = "http://sbi-update-kyc.com/login"
    print("Link Analysis Test Result:")
    print(analyze_link(test_url))