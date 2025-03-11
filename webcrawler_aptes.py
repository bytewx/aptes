import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin, urlparse

def get_links(url, visited):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        return set()  # Return a set instead of a list
    
    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()  # Use a set to store unique links
    
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(url, href)
        parsed_url = urlparse(full_url)

        if parsed_url.path and parsed_url.path != '/' and full_url not in visited:
            links.add(full_url)

    return links

def enumerate_directories(domain):
    visited = set()
    pending = {domain}

    print(f"[+] Enumerating directories on {domain}\n")

    while pending:
        current_url = pending.pop()
        visited.add(current_url)

        print(f"[FOUND] {current_url}")

        new_links = get_links(current_url, visited)
        pending.update(new_links - visited)  # Now new_links is a set, so this works fine

if name == "main":
    if len(sys.argv) != 2:
        print("Usage: python aptes.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    if not domain.startswith("http"):
        domain = "http://" + domain

    enumerate_directories(domain)
