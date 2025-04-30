#!/usr/bin/env python3
"""
Web crawler module for APTES using Scrapy - with multi-target support
"""

import os
import tempfile
import logging
import json
import time
import sys
import asyncio
from urllib.parse import urlparse, urljoin
import subprocess
from threading import Lock

logger = logging.getLogger('aptes.webcrawler')

# Check for Scrapy
try:
    import scrapy
    from scrapy.crawler import CrawlerRunner
    from scrapy.utils.project import get_project_settings
    from scrapy.utils.log import configure_logging
    from scrapy.spiders import CrawlSpider, Rule
    from scrapy.linkextractors import LinkExtractor
    from twisted.internet import reactor
    import twisted.internet.error
    from scrapy.utils.reactor import install_reactor
    SCRAPY_AVAILABLE = True
except ImportError:
    SCRAPY_AVAILABLE = False
    logger.warning("Scrapy not available - web crawling disabled")

# Flag to track if reactor is running
reactor_running = False
reactor_lock = Lock()

class SitemapItem(scrapy.Item):
    """Scrapy Item to store page information"""
    url = scrapy.Field()
    title = scrapy.Field()
    links = scrapy.Field()
    status = scrapy.Field()
    content_type = scrapy.Field()
    depth = scrapy.Field()
    forms = scrapy.Field()
    inputs = scrapy.Field()
    scripts = scrapy.Field()


class APTESSitemapSpider(CrawlSpider):
    """Spider for crawling websites and generating sitemap"""
    name = 'sitemap_spider'
    
    def __init__(self, target_url=None, domains=None, max_depth=2, output_file=None, *args, **kwargs):
        self.output_file = output_file
        self.items_scraped = []
        
        # Handle domains correctly
        if target_url:
            self.start_urls = [target_url]
            
            # Extract domain from URL
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            # Strip port from domain
            if ':' in domain:
                domain = domain.split(':', 1)[0]
                
            if domains:
                self.allowed_domains = domains if isinstance(domains, list) else [domains]
            else:
                self.allowed_domains = [domain]
        
        # Compile patterns for extracting forms, inputs, and scripts
        import re
        self.form_pattern = re.compile(r'<form[^>]*>.*?</form>', re.DOTALL)
        self.input_pattern = re.compile(r'<input[^>]*>', re.DOTALL)
        self.script_pattern = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL)
        
        # Set maximum crawl depth
        self.max_depth = max_depth
        
        # Initialize sitemap
        self.sitemap = {}
        
        super(APTESSitemapSpider, self).__init__(*args, **kwargs)
        
        # Set up crawler rules - must be after super() init
        self.rules = (
            Rule(LinkExtractor(allow_domains=self.allowed_domains), callback='parse_page', follow=True),
        )
    
    def parse_page(self, response):
        """Parse a page and extract information"""
        # Skip if we've reached max depth
        depth = response.meta.get('depth', 0)
        if depth > self.max_depth:
            return None
        
        # Extract page information
        url = response.url
        title = response.css('title::text').get()
        
        # Extract links
        links = []
        for href in response.css('a::attr(href)').getall():
            absolute_url = urljoin(response.url, href)
            parsed = urlparse(absolute_url)
            if parsed.netloc.split(':', 1)[0] in self.allowed_domains:
                links.append(absolute_url)
        
        # Extract forms
        forms = []
        for form_html in self.form_pattern.findall(response.text):
            form_info = {
                'action': None,
                'method': 'GET',
                'inputs': []
            }
            
            # Extract form attributes
            form_action_match = re.search(r'action=["\'](.*?)["\']', form_html)
            if form_action_match:
                form_info['action'] = urljoin(response.url, form_action_match.group(1))
            
            form_method_match = re.search(r'method=["\'](.*?)["\']', form_html)
            if form_method_match:
                form_info['method'] = form_method_match.group(1).upper()
            
            # Extract inputs
            for input_html in self.input_pattern.findall(form_html):
                input_info = {'type': 'text', 'name': None, 'value': None}
                
                input_type_match = re.search(r'type=["\'](.*?)["\']', input_html)
                if input_type_match:
                    input_info['type'] = input_type_match.group(1)
                
                input_name_match = re.search(r'name=["\'](.*?)["\']', input_html)
                if input_name_match:
                    input_info['name'] = input_name_match.group(1)
                
                input_value_match = re.search(r'value=["\'](.*?)["\']', input_html)
                if input_value_match:
                    input_info['value'] = input_value_match.group(1)
                
                form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        # Extract scripts
        scripts = []
        for script_html in self.script_pattern.findall(response.text):
            script_src_match = re.search(r'src=["\'](.*?)["\']', script_html)
            if script_src_match:
                scripts.append(urljoin(response.url, script_src_match.group(1)))
        
        # Store page information in sitemap
        page_info = {
            'url': url,
            'title': title,
            'links': links,
            'status': response.status,
            'content_type': response.headers.get('Content-Type', b'').decode('utf-8', errors='ignore'),
            'depth': depth,
            'forms': forms,
            'inputs': len(sum([form['inputs'] for form in forms], [])) if forms else 0,
            'scripts': scripts
        }
        
        self.sitemap[url] = page_info
        
        # Add to our items list
        self.items_scraped.append(page_info)
        
        # Return as Scrapy item
        item = SitemapItem()
        item.update(page_info)
        return item
    
    def closed(self, reason):
        """Called when crawler is closed"""
        logger.info(f"Crawler finished: {reason}")
        logger.info(f"Crawled {len(self.sitemap)} pages")
        
        # Save results directly
        if self.output_file and self.items_scraped:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(self.items_scraped, f, indent=4)
                logger.info(f"Saved {len(self.items_scraped)} crawled pages to {self.output_file}")
            except Exception as e:
                logger.error(f"Error saving results to {self.output_file}: {str(e)}")


# Alternative approach: Run scrapy as a separate process to avoid reactor issues
def run_scrapy_subprocess(target_url, output_file, max_depth=2, domains=None):
    """
    Run Scrapy as a separate process to avoid reactor issues
    
    Args:
        target_url (str): URL to crawl
        output_file (str): File to save results to
        max_depth (int): Maximum crawl depth
        domains (list): List of allowed domains
        
    Returns:
        bool: True if subprocess completed successfully
    """
    # Create a temporary spider file
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
        spider_file = f.name
        
        # Write a standalone spider script - properly escaping the regex patterns
        f.write(f"""#!/usr/bin/env python3
import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
import json
import re
from urllib.parse import urlparse, urljoin

class SitemapSpider(CrawlSpider):
    name = 'sitemap_spider'
    
    def __init__(self, *args, **kwargs):
        self.start_urls = ['{target_url}']
        parsed_url = urlparse('{target_url}')
        domain = parsed_url.netloc.split(':', 1)[0]
        self.allowed_domains = [domain]
        
        self.form_pattern = re.compile(r'<form[^>]*>.*?</form>', re.DOTALL)
        self.input_pattern = re.compile(r'<input[^>]*>', re.DOTALL)
        self.script_pattern = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL)
        
        self.max_depth = {max_depth}
        self.items_scraped = []
        
        super(SitemapSpider, self).__init__(*args, **kwargs)
        
        self.rules = (
            Rule(LinkExtractor(allow_domains=self.allowed_domains), callback='parse_page', follow=True),
        )
    
    def parse_page(self, response):
        # Skip if we've reached max depth
        depth = response.meta.get('depth', 0)
        if depth > self.max_depth:
            return None
        
        url = response.url
        title = response.css('title::text').get()
        
        # Extract links
        links = []
        for href in response.css('a::attr(href)').getall():
            absolute_url = urljoin(response.url, href)
            links.append(absolute_url)
        
        # Extract forms
        forms = []
        for form_html in self.form_pattern.findall(response.text):
            form_info = {{
                'action': None,
                'method': 'GET',
                'inputs': []
            }}
            
            # FIXED REGEX PATTERNS - properly escaped
            form_action_match = re.search(r'action=["\\\']([^\\\'"]*)["\\\']', form_html)
            if form_action_match:
                form_info['action'] = urljoin(response.url, form_action_match.group(1))
            
            form_method_match = re.search(r'method=["\\\']([^\\\'"]*)["\\\']', form_html)
            if form_method_match:
                form_info['method'] = form_method_match.group(1).upper()
            
            # Extract inputs
            for input_html in self.input_pattern.findall(form_html):
                input_info = {{'type': 'text', 'name': None, 'value': None}}
                
                input_type_match = re.search(r'type=["\\\']([^\\\'"]*)["\\\']', input_html)
                if input_type_match:
                    input_info['type'] = input_type_match.group(1)
                
                input_name_match = re.search(r'name=["\\\']([^\\\'"]*)["\\\']', input_html)
                if input_name_match:
                    input_info['name'] = input_name_match.group(1)
                
                input_value_match = re.search(r'value=["\\\']([^\\\'"]*)["\\\']', input_html)
                if input_value_match:
                    input_info['value'] = input_value_match.group(1)
                
                form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        # Extract scripts
        scripts = []
        for script_html in self.script_pattern.findall(response.text):
            script_src_match = re.search(r'src=["\\\']([^\\\'"]*)["\\\']', script_html)
            if script_src_match:
                scripts.append(urljoin(response.url, script_src_match.group(1)))
        
        # Create page info
        page_info = {{
            'url': url,
            'title': title,
            'links': links,
            'status': response.status,
            'content_type': response.headers.get('Content-Type', b'').decode('utf-8', errors='ignore'),
            'depth': depth,
            'forms': forms,
            'inputs': len(sum([form['inputs'] for form in forms], [])) if forms else 0,
            'scripts': scripts
        }}
        
        # Save to our items list
        self.items_scraped.append(page_info)
        
        # Store result for export as a pipeline would
        with open("{output_file}", 'w') as f:
            json.dump(self.items_scraped, f, indent=4)
        
        return page_info

# Configure settings and run the spider
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

if __name__ == "__main__":
    settings = get_project_settings()
    settings.update({{
        'USER_AGENT': 'APTES Crawler (+https://github.com/byteshell/aptes)',
        'ROBOTSTXT_OBEY': True,
        'CONCURRENT_REQUESTS': 8,
        'DOWNLOAD_DELAY': 0.5,
        'COOKIES_ENABLED': True,
        'LOG_LEVEL': 'INFO',
        'DEPTH_LIMIT': {max_depth}
    }})
    
    process = CrawlerProcess(settings)
    process.crawl(SitemapSpider)
    process.start()
""")
    
    try:
        # Run the spider
        logger.info(f"Running Scrapy subprocess for {target_url}")
        result = subprocess.run(
            [sys.executable, spider_file],
            text=True,
            capture_output=True,
            timeout=180  # 3 minute timeout
        )
        
        # Check for success and log output
        if result.returncode == 0:
            logger.info(f"Scrapy subprocess completed successfully for {target_url}")
            # Log a subset of the stdout for debugging
            if result.stdout:
                logger.debug(f"Subprocess output (first 500 chars): {result.stdout[:500]}")
        else:
            logger.error(f"Scrapy subprocess failed for {target_url}: {result.stderr}")
            if result.stdout:
                logger.debug(f"Subprocess stdout (first 500 chars): {result.stdout[:500]}")
        
        # Clean up the temporary file
        try:
            os.unlink(spider_file)
        except Exception as e:
            logger.warning(f"Failed to remove temporary file {spider_file}: {str(e)}")
        
        return result.returncode == 0
            
    except subprocess.TimeoutExpired:
        logger.error(f"Scrapy subprocess timed out for {target_url}")
        # Clean up the temporary file
        try:
            os.unlink(spider_file)
        except:
            pass
        return False
    except Exception as e:
        logger.error(f"Error running Scrapy subprocess for {target_url}: {str(e)}")
        # Clean up the temporary file
        try:
            os.unlink(spider_file)
        except:
            pass
        return False


# Simple function to directly visit a URL and check basic info
def simple_url_check(url):
    """
    Simple function to check a URL without using Scrapy
    
    Args:
        url (str): URL to check
        
    Returns:
        dict: Basic information about the URL
    """
    try:
        import requests
        from bs4 import BeautifulSoup
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        logger.info(f"Performing simple check on {url}")
        
        response = requests.get(url, timeout=10, verify=False)
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract title
        title = soup.title.string if soup.title else "No title"
        
        # Extract links
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if not href.startswith('http'):
                href = urljoin(url, href)
            links.append(href)
        
        # Extract forms
        forms = []
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Extract inputs
            for input_tag in form.find_all('input'):
                input_info = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                }
                form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        return {
            "url": url,
            "title": title,
            "status": response.status_code,
            "content_type": response.headers.get('Content-Type', ''),
            "links": links,
            "forms": forms,
            "inputs": sum(len(form['inputs']) for form in forms)
        }
    
    except Exception as e:
        logger.error(f"Error in simple URL check: {str(e)}")
        return {
            "url": url,
            "error": str(e)
        }


def crawl_website(target_url, output_file=None, max_depth=2, domains=None):
    """
    Crawl a website and generate a sitemap
    
    Args:
        target_url (str): URL to start crawling from
        output_file (str): File to save the results to
        max_depth (int): Maximum crawl depth
        domains (list): List of allowed domains
    
    Returns:
        dict: Sitemap data structure
    """
    if not SCRAPY_AVAILABLE:
        logger.error("Scrapy is not available, cannot crawl website")
        return {
            "error": "Scrapy not available",
            "crawled_urls": 0,
            "sitemap": {}
        }
    
    logger.info(f"Starting web crawl on {target_url}")
    
    # Create temporary file if output file not provided
    if not output_file:
        temp_dir = tempfile.mkdtemp(prefix="aptes_crawler_")
        output_file = os.path.join(temp_dir, "sitemap.json")
    
    logger.info(f"Using output file: {output_file}")
    
    try:
        # Run scrapy as a subprocess to avoid reactor issues
        subprocess_success = run_scrapy_subprocess(
            target_url=target_url,
            output_file=output_file,
            max_depth=max_depth,
            domains=domains
        )
        
        # Load results from output file
        sitemap_items = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    sitemap_items = json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error parsing JSON from {output_file}")
                sitemap_items = []
        else:
            logger.error(f"Output file {output_file} not found")
            
            # If subprocess failed or file doesn't exist, try the simple approach
            try:
                logger.info(f"Trying simple URL check for {target_url}")
                simple_result = simple_url_check(target_url)
                if 'error' not in simple_result:
                    sitemap_items = [simple_result]
                    # Save the simple result
                    with open(output_file, 'w') as f:
                        json.dump(sitemap_items, f, indent=4)
            except Exception as e:
                logger.error(f"Simple URL check failed: {str(e)}")
        
        # If no results at all, try the simple approach as a fallback
        if not sitemap_items:
            try:
                logger.info(f"No results from crawl, trying simple URL check for {target_url}")
                simple_result = simple_url_check(target_url)
                if 'error' not in simple_result:
                    sitemap_items = [simple_result]
                    # Save the simple result
                    with open(output_file, 'w') as f:
                        json.dump(sitemap_items, f, indent=4)
            except Exception as e:
                logger.error(f"Simple URL check failed: {str(e)}")
        
        # Convert to sitemap structure
        sitemap = {}
        for item in sitemap_items:
            sitemap[item['url']] = item
        
        # Calculate statistics
        form_urls = [url for url, data in sitemap.items() if data.get('forms')]
        potential_vuln_urls = [url for url, data in sitemap.items() 
                            if '?' in url or data.get('inputs', 0) > 0]
        
        results = {
            "crawled_urls": len(sitemap),
            "max_depth": max_depth,
            "start_url": target_url,
            "forms_found": sum(len(data.get('forms', [])) for data in sitemap.values()),
            "form_urls": form_urls,
            "potential_vulnerable_urls": potential_vuln_urls,
            "sitemap": sitemap
        }
        
        logger.info(f"Web crawl complete: {len(sitemap)} pages crawled")
        return results
    
    except Exception as e:
        logger.error(f"Error in web crawl: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        
        # Try the simple approach as a fallback
        try:
            logger.info(f"Trying simple URL check for {target_url}")
            simple_result = simple_url_check(target_url)
            if 'error' not in simple_result:
                sitemap = {simple_result['url']: simple_result}
                form_urls = [url for url, data in sitemap.items() if data.get('forms')]
                potential_vuln_urls = [url for url, data in sitemap.items() 
                                    if '?' in url or data.get('inputs', 0) > 0]
                
                results = {
                    "crawled_urls": len(sitemap),
                    "max_depth": max_depth,
                    "start_url": target_url,
                    "forms_found": sum(len(data.get('forms', [])) for data in sitemap.values()),
                    "form_urls": form_urls,
                    "potential_vulnerable_urls": potential_vuln_urls,
                    "sitemap": sitemap
                }
                
                # Save the simple result
                with open(output_file, 'w') as f:
                    json.dump([simple_result], f, indent=4)
                
                return results
        except Exception as e2:
            logger.error(f"Simple URL check failed as well: {str(e2)}")
        
        return {
            "error": str(e),
            "crawled_urls": 0,
            "sitemap": {}
        }


def check_scrapy_installation():
    """
    Check if Scrapy is installed
    
    Returns:
        bool: True if Scrapy is installed, False otherwise
    """
    return SCRAPY_AVAILABLE


if __name__ == "__main__":
    """Test the crawler module"""
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python webcrawler.py <target_url> [output_file] [max_depth]")
        sys.exit(1)
    
    target_url = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    max_depth = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    
    results = crawl_website(target_url, output_file, max_depth)
    
    print(f"Crawled {results['crawled_urls']} pages")
    print(f"Found {results['forms_found']} forms")
    print(f"Potential vulnerable URLs: {len(results['potential_vulnerable_urls'])}")
