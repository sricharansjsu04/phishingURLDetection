import pickle
from urllib.parse import urlparse
import ipaddress
import re
from datetime import datetime
import whois
import requests
from bs4 import BeautifulSoup
import numpy as np
import xgboost as xgb
import phishingllm

# Define individual feature extraction functions
def havingIP(url):
    """Check if URL contains an IP address."""
    try:
        ipaddress.ip_address(url)
        return 1
    except ValueError:
        return 0

def haveAtSign(url):
    """Check if URL contains '@' symbol."""
    return 1 if "@" in url else 0

def getLength(url):
    """Check if URL length is >= 54 characters."""
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    """Calculate the depth of the URL path based on '/'."""
    return sum(1 for part in urlparse(url).path.split('/') if part)

def redirection(url):
    """Check if URL contains '//' after the protocol."""
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

def httpDomain(url):
    """Check if 'https' exists in the domain part of the URL."""
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

def tinyURL(url):
    """Check if URL uses a shortening service."""
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|t\.co|tinyurl"
    return 1 if re.search(shortening_services, url) else 0

def prefixSuffix(url):
    """Check if the domain contains a '-' symbol."""
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    """Check the web traffic ranking using Alexa data."""
    try:
        url_encoded = urllib.parse.quote(url)
        rank = int(BeautifulSoup(urllib.request.urlopen(
            f"http://data.alexa.com/data?cli=10&dat=s&url={url_encoded}").read(), "xml").find("REACH")['RANK'])
        print("ranks is ", rank)
        return 1 if rank < 100000 else 0
        
    except Exception:
        return 1

def domainAge(domain_name):
    """Calculate the age of the domain in days."""
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if not creation_date or not expiration_date:
            return 1
        age = (expiration_date - creation_date).days
        return 0 if age >= 365 else 1
    except Exception:
        return 1

def domainEnd(domain_name):
    """Check if the domain expires within 180 days."""
    try:
        expiration_date = domain_name.expiration_date
        if not expiration_date:
            return 1
        remaining_days = (expiration_date - datetime.now()).days
        return 1 if remaining_days <= 180 else 0
    except Exception:
        return 1

def iframe(response):
    """Check if the response contains iframe or frameBorder."""
    if response == "":
        return 1
    return 1 if re.search(r"<iframe>|<frameBorder>", response.text) else 0

def mouseOver(response):
    """Check for onmouseover events in JavaScript."""
    if response == "":
        return 1
    return 1 if re.search(r"<script>.+onmouseover.+</script>", response.text) else 0

def rightClick(response):
    """Check if right-click is disabled via JavaScript."""
    if response == "":
        return 1
    return 1 if re.search(r"event.button==2", response.text) else 0

def forwarding(response):
    """Check if the URL has multiple redirections."""
    if response == "":
        return 1
    return 1 if len(response.history) > 2 else 0

# Function to extract all features for a given URL
def extract_features(url):
    features = []
    
    # Address bar-based features
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))
    
    # Domain-based features
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        dns = 0
    except Exception:
        dns = 1
    
    features.append(dns)
    features.append(web_traffic(url) if dns == 0 else 1)
    features.append(domainAge(domain_name) if dns == 0 else 1)
    features.append(domainEnd(domain_name) if dns == 0 else 1)
    
    # HTML & JavaScript-based features
    try:
        response = requests.get(url, timeout=5)
    except Exception:
        response = ""
    
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
    
    return features

# Feature names for reference
feature_names = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
    "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record",
    "Web_Traffic", "Domain_Age", "Domain_End", "iFrame",
    "Mouse_Over", "Right_Click", "Web_Forwards"
]

# Load the saved XGBoost model
model_path = "XGBoostClassifier.json"
model = xgb.Booster()
model.load_model(model_path)

# Function to predict if a URL is phishing or legitimate
def predict_url(url):
    # Extract features from the URL
    features = extract_features(url)
    X_test = np.array(features).reshape(1, -1)

    # Predict using the loaded model
    dmatrix = xgb.DMatrix(X_test, feature_names=feature_names)
    prediction = model.predict(dmatrix)

    return prediction[0]

# Example usage
if __name__ == "__main__":
    test_url = "https://example.com"
    print("Extracted Features:", extract_features(test_url))
    print("Prediction:", predict_url(test_url))
