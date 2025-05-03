import re
import ssl
import socket
from datetime import datetime
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

TRUSTED_ISSUERS = {"GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign", "Sectigo Limited"}

def extract_features(url, return_meta=False):
    # At the top of extract_features
    if not url.startswith("http"):
        url = "https://" + url
    features = []
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    
    # 1. having_IP_Address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) or re.match(r"(0x)?[0-9a-fA-F]+", hostname):
        features.append(-1)
    else:
        features.append(1)

    # 2. URL_Length
    if len(url) < 54:
        features.append(1)
    else:
        features.append(-1)

    # 3. Shortining_Service
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'tiny.cc', 'is.gd', 'buff.ly']
    if any(service in url for service in shortening_services):
        features.append(-1)
    else:
        features.append(1)

    # 4. having_At_Symbol
    features.append(-1 if "@" in url else 1)

    # 5. double_slash_redirecting
    if url.find('//') > 7:
        features.append(-1)
    else:
        features.append(1)

    # 6. Prefix_Suffix
    if '-' in hostname:
        features.append(-1)
    else:
        features.append(1)

    # 7. having_Sub_Domain
    dots = hostname.count('.')
    if dots == 1:
        features.append(0)
    elif dots > 1:
        features.append(-1)
    else:
        features.append(1)
    
    # 8. SSLfinal_State
    ssl_state = 1
    try:
        # Increased timeout to avoid connection issues
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)  # Increased timeout to 5 seconds
            print(f"Connecting to {hostname}...")
            s.connect((hostname, 443))  # Try connecting to the SSL port
            cert = s.getpeercert()  # Get SSL certificate
            
            # Log certificate details to help debug
            print(f"Certificate details for {hostname}: {cert}")
            
            # Extract certificate issue date and calculate age
            not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            age_days = (datetime.utcnow() - not_before).days
            issuer = dict(x[0] for x in cert['issuer']).get('organizationName', "")
            print(f"Certificate age: {age_days} days, Issuer: {issuer}")

            # Check certificate age and issuer validity
            if age_days < 60 or issuer not in TRUSTED_ISSUERS:
                ssl_state = -1  # Mark as suspicious if conditions are met
    except ssl.SSLError as e:
        print(f"SSL Error for {hostname}: {e}")
        ssl_state = -1  # If SSL error occurs, mark as suspicious
    except socket.timeout as e:
        print(f"Timeout error for {hostname}: {e}")
        ssl_state = -1  # Timeout should be treated as suspicious
    except Exception as e:
        print(f"General error for {hostname}: {e}")
        ssl_state = -1  # Handle any other unexpected errors

    features.append(ssl_state)

    # 9. Domain_registration_length (from WHOIS)
    reg_length = -1
    try:
        w = whois.whois(hostname)
        creation = w.creation_date
        expiration = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiration, list): expiration = expiration[0]
        if expiration and creation and (expiration - creation).days >= 365:
            reg_length = 1
    except Exception as e:
        print(f"WHOIS failed for {hostname}: {e}")
        reg_length = -1
    features.append(reg_length)

    # 10. Favicon
    fav = 1
    try:
        r = requests.get(url, timeout=3)
        soup = BeautifulSoup(r.text, 'html.parser')
        icon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if icon and 'href' in icon.attrs:
            href = icon['href']
            fav_domain = urlparse(href if href.startswith('http') else url + href).netloc
            if fav_domain and fav_domain != hostname:
                fav = -1
    except Exception:
        fav = -1
    features.append(fav)

    # 11. port
    port_val = parsed.port
    if port_val and port_val not in (80, 443):
        features.append(-1)
    else:
        features.append(1)

    # 12. HTTPS_token
    # if “https” appears in domain portion (not protocol), that’s suspicious
    features.append(-1 if 'https' in hostname.lower() else 1)

    # fetch HTML once for reuse
    html = ""
    soup = None  # ← initialize soup to avoid UnboundLocalError

    try:
        resp = requests.get(url, timeout=5)
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')
        history_len = len(resp.history)
    except Exception as e:
        print("Error fetching page:", e)
        soup = BeautifulSoup("", 'html.parser')  # ← fallback to empty soup
        history_len = 0

    # 13. Request_URL
    req = 1
    for tag in soup.find_all(src=True):
         src_dom = urlparse(tag['src']).netloc
         # if it’s not empty and not a sub-domain of hostname
         if src_dom and not src_dom.endswith(hostname):
             req = -1
             break
    features.append(req)

    # 14. URL_of_Anchor
    anchor = 1
    for a in soup.find_all('a', href=True):
         href = a['href']
         if href.startswith('#') or 'javascript:void' in href.lower():
            anchor = -1
            break
         ann_dom = urlparse(a['href']).netloc
         if ann_dom and not ann_dom.endswith(hostname):
             anchor = -1
             break
    features.append(anchor)

    # 15. Links_in_tags (<meta>, <script>, <link>)
    tags_ok = 1
    try:
        for t in BeautifulSoup(r.text, 'html.parser').find_all(['meta','script','link'], src=True, href=True):
            dom = urlparse(t.get('src',t.get('href'))).netloc
            if dom and dom != hostname:
                tags_ok = -1
                break
    except Exception:
        tags_ok = -1
    features.append(tags_ok)

    # 16. SFH (Server Form Handler)
    sfh = 1
    for form in soup.find_all('form', action=True):
        action = form['action']
        a_dom = urlparse(action).netloc
        if (a_dom and not a_dom.endswith(hostname)) or action.lower() == "about:blank":
            sfh = -1
            break
    features.append(sfh)

    # 17. Submitting_to_email
    mail = 1
    if re.search(r"mail\(.*\)|mailto:", html, re.IGNORECASE):
        mail = -1
    features.append(mail)

    # 18. Abnormal_URL (check if domain part appears in URL path)
    abnormal = 1
    if hostname not in url:
        abnormal = -1
    features.append(abnormal)

    # 19. Redirect (website forwarding count)
    # legitimate ≤1 redirect, phishing ≥4
    if history_len <= 1:
        features.append(1)
    elif history_len >= 4:
        features.append(-1)
    else:
        features.append(0)

    # 20. on_mouseover (status bar customization)
    features.append(-1 if "onmouseover" in html.lower() else 1)

    # 21. RightClick disabled
    features.append(-1 if re.search(r"event.button\s*==\s*2", html) else 1)

    # 22. popUpWindow
    features.append(-1 if "window.open" in html else 1)

    # 23. Iframe redirection
    iframe = soup.find_all('iframe')
    features.append(-1 if len(iframe)>0 else 1)

    # 24. age_of_domain (days since creation)
    age = -1
    try:
        w = whois.whois(hostname)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        if creation:
            days = (datetime.utcnow() - creation).days
            age = 1 if days >= 180 else -1
    except Exception as e:
        print(f"WHOIS failed for {hostname}: {e}")
        age = -1
    features.append(age)

    # 25. DNSRecord
    try:
        socket.gethostbyname(hostname)
        features.append(1)
    except:
        features.append(-1)

    # 26. web_traffic (stub — hook to Alexa or SimilarWeb API)
    features.append(1)  

    # 27. Page_Rank (stub — hook to PageRank API)
    features.append(1)

    # 28. Google_Index (stub — hook to Google Search API)
    features.append(1)

    # 29. Links_pointing_to_page
    links = soup.find_all('a', href=True)
    ext = 0
    for a in links:
        d = urlparse(a['href']).netloc
        if d and d != hostname:
            ext += 1
    features.append(1 if ext >= 2 else -1)

    # 30. Statistical_report (stub — hook to PhishTank/StopBadware)
    features.append(1)
    
    # Build a list of “human readable” flag names for any -1 features:
    feature_names = [
        'IP Address', 'URL Length', 'Shortening Service', 'At Symbol',
        'Double Slash Redirect', 'Prefix/Suffix', 'Subdomain Count',
        'SSL State', 'Domain Registration Length', 'Favicon Domain',
        'Port', 'HTTPS Token', 'External Resources', 'External Anchors',
        'Links In Tags', 'SFH', 'Email Submission', 'Abnormal URL',
        'Redirect Count', 'Mouseover JS', 'RightClick JS', 'Popup JS',
        'IFrame', 'Domain Age', 'DNS Record', 'Web Traffic', 'PageRank',
        'Google Index', 'Backlinks', 'Statistical Report'
    ]
    red_flags = [n for n, val in zip(feature_names, features) if val == -1]

    # Package up meta info
    meta = {
        'domain': hostname,
        'issuer': issuer if 'issuer' in locals() else None,
        'cert_age': age_days if 'age_days' in locals() else None,
        'domain_age': days if 'days' in locals() else None,
        'red_flags': red_flags
    }
    print(f"Extracted features for: {url}")

    # Manually penalize if all critical checks fail
    if ssl_state == -1 and reg_length == -1:
        print("❗Critical checks failed (SSL and WHOIS). Penalizing features...")
        features = [-1 if f == 1 else f for f in features]

        if return_meta:
            meta = {
                "domain": hostname,
                "issuer": issuer if 'issuer' in locals() else "Unknown",
                "cert_age": age_days if 'age_days' in locals() else "N/A",
                "domain_age": days if 'days' in locals() else "N/A",
                "red_flags": []
            }

            if ssl_state == -1:
                meta["red_flags"].append("Untrusted or young SSL certificate")
            if reg_length == -1:
                meta["red_flags"].append("WHOIS info missing or short registration")
            if age == -1:
                meta["red_flags"].append("Domain age too short")
            if abnormal == -1:
                meta["red_flags"].append("Abnormal URL structure")
            if sfh == -1:
                meta["red_flags"].append("Suspicious form handler")
            if mail == -1:
                meta["red_flags"].append("Email submission found")
            if req == -1 or anchor == -1:
                meta["red_flags"].append("External resource linking")
        return features, meta

    return features, meta
