import re

def is_phishing(url):
    # Basic rules for phishing detection
    features = {
        "Long URL": len(url) > 50,
        "Contains @ symbol": "@" in url,
        "Contains IP address": bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
        "Multiple subdomains": url.count('.') > 3,
        "Suspicious Keywords": any(word in url.lower() for word in ['login', 'verify', 'bank', 'secure', 'update', 'free'])
    }
    
    score = sum(features.values())
    
    print(f"\nAnalyzing: {url}")
    for feature, found in features.items():
        if found:
            print(f"[!] Warning: {feature}")
            
    if score >= 2:
        return "RESULT: HIGH RISK (Possible Phishing Link)"
    else:
        return "RESULT: LOW RISK (Likely Safe)"

# Testing
if __name__ == "__main__":
    link = input("Enter the URL to check: ")
    print(is_phishing(link))
