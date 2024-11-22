import re
import requests
import joblib
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import numpy as np

# Load the trained model from the .pkl file using joblib
model = joblib.load(r"C:\Users\Jonriel Baloyo\OneDrive\Dokumen\Thesis\xgb_phishing\xgboost_model.pkl")

def is_external_link(url, base_domain):
    """Check if the URL is external compared to the base domain."""
    parsed_url = urlparse(url)
    return parsed_url.netloc and parsed_url.netloc != base_domain

def check_link(url):
    """Check if a link is valid or broken. Returns True if valid, False if broken."""
    try:
        response = requests.head(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def extract_external_error_ratio(soup, base_domain):
    """Calculate the ratio of broken external links to total external links."""
    external_links = [a['href'] for a in soup.find_all('a', href=True) if is_external_link(a['href'], base_domain)]
    
    if not external_links:
        return 0  # No external links, so error ratio is 0

    # Check each external link and count errors
    external_errors = sum(not check_link(link) for link in external_links)
    ratio_ext_errors = external_errors / len(external_links)

    return ratio_ext_errors

def extract_features_from_url(url):
    features = {}

    # Parse URL components
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # Existing feature extraction logic
    features["NumDots"] = hostname.count(".")
    features["SubdomainLevel"] = len(hostname.split(".")) - 2
    features["PathLevel"] = path.count("/")
    features["UrlLength"] = len(url)
    features["NumDash"] = url.count("-")
    features["NumDashInHostname"] = hostname.count("-")
    features["AtSymbol"] = "@" in url
    features["TildeSymbol"] = "~" in url
    features["NumUnderscore"] = url.count("_")
    features["NumPercent"] = url.count("%")
    features["NumQueryComponents"] = len(parse_qs(query))
    features["NumAmpersand"] = url.count("&")
    features["NumHash"] = url.count("#")
    features["NumNumericChars"] = sum(c.isdigit() for c in hostname)
    features["NoHttps"] = int(parsed_url.scheme != "https")
    features["RandomString"] = int(bool(re.search(r'[a-zA-Z0-9]{7,}', hostname)))
    features["IpAddress"] = int(bool(re.match(r'\b\d{1,3}(\.\d{1,3}){3}\b', hostname)))
    features["DomainInSubdomains"] = int("domain" in hostname.split(".")[:-2])
    features["DomainInPaths"] = int("domain" in path)
    features["HttpsInHostname"] = int("https" in hostname)
    features["HostnameLength"] = len(hostname)
    features["PathLength"] = len(path)
    features["QueryLength"] = len(query)
    features["DoubleSlashInPath"] = int("//" in path)
    sensitive_words = ["secure", "account", "webscr", "login", "signin"]
    features["NumSensitiveWords"] = sum(word in url.lower() for word in sensitive_words)
    brand_names = ["paypal", "google", "facebook", "amazon"]
    features["EmbeddedBrandName"] = int(any(brand in hostname for brand in brand_names))

    # HTML-based features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        ext_links = [link['href'] for link in soup.find_all('a', href=True) if hostname not in link['href']]
        features["PctExtHyperlinks"] = (len(ext_links) / len(soup.find_all('a', href=True))) * 100 if soup.find_all('a', href=True) else 0
        ext_resources = [link['src'] for link in soup.find_all(src=True) if hostname not in link['src']]
        features["PctExtResourceUrls"] = (len(ext_resources) / len(soup.find_all(src=True))) * 100 if soup.find_all(src=True) else 0
        favicon = soup.find("link", rel="icon")
        features["ExtFavicon"] = int(favicon and hostname not in favicon.get("href", ""))
        insecure_forms = [form for form in soup.find_all("form") if not form.get("action", "").startswith("https")]
        features["InsecureForms"] = int(bool(insecure_forms))
        
        # 48. RatioExtErrors - Apply the feature logic
        features["RatioExtErrors"] = extract_external_error_ratio(soup, hostname)

    except Exception as e:
        # If HTML fetching or parsing fails, default to 0 or NaN for HTML-based features
        features.update({"PctExtHyperlinks": np.nan, "PctExtResourceUrls": np.nan, "ExtFavicon": 0, "InsecureForms": 0})
    
    # Additional features...
    features["RatioDigitsHost"] = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0
    features["DomainAge"] = len(parsed_url.hostname)  # Placeholder for domain age logic
    features["HashtagInUrl"] = int("#" in url)
    features["WwwInHostname"] = int("www" in hostname)
    suspicious_tlds = ["xyz", "top", "club", "win"]
    features["SuspiciousTLD"] = int(hostname.split('.')[-1] in suspicious_tlds)
    features["SuspiciousDomain"] = int("malicious" in hostname or "phishing" in hostname)
    features["PathContainsQuery"] = int("?" in path)
    features["LengthOfQuery"] = len(query)
    features["QueryHasEqualSigns"] = int("=" in query)
    path_keywords = ["login", "signin", "account"]
    features["PathContainsSensitiveKeywords"] = int(any(keyword in path.lower() for keyword in path_keywords))
    features["ExternalLinksInPage"] = int(bool(soup.find_all("a", href=True)))
    features["EmbeddedIframe"] = int(bool(soup.find_all("iframe")))
    features["NumSubdomains"] = len(hostname.split(".")) - 2
    features["PathContainsSlashes"] = int("/" in path)
    features["NumRedirects"] = url.count("redirect")
    features["DomainInUrl"] = int("domain" in url)
    features["SecureForms"] = int(bool(soup.find_all("form", action=True) and all(form["action"].startswith("https") for form in soup.find_all("form"))))

    return features

def predict_phishing(url):
    # Extract features from the URL
    features = extract_features_from_url(url)

    # Align features with model input
    model_features = [features[key] for key in sorted(features.keys())]

    # Predict probabilities
    probabilities = model.predict_proba([model_features])

    # Print extracted features and prediction probabilities
    for key, value in features.items():
        print(f"{key}: {value}")

    legit_prob = probabilities[0][0]
    phishing_prob = probabilities[0][1]
    
     # Print the probabilities
    print(f"Legitimate Probability: {legit_prob}")
    print(f"Phishing Probability: {phishing_prob}")

    # Determine prediction
    prediction = "Phishing" if phishing_prob > legit_prob else "Legitimate"
    
    return prediction

# Example URL for testing
url = "https://masaolms.carsu.edu.ph/"
prediction = predict_phishing(url)
print("Prediction:", prediction)
