#!/usr/bin/env python3
"""
Web crawler module for APTES using Scrapy
"""

import os
import re
import tempfile
import logging
import json
from urllib.parse import urlparse, urljoin
import time
import sys

logger = logging.getLogger('aptes.webcrawler')

# Check for Scrapy
try:
    import scrapy
    from scrapy.crawler import CrawlerProcess
    from scrapy.utils.project import get_project_settings
    from scrapy.spiders import CrawlSpider, Rule
    from scrapy.linkextractors import LinkExtractor
    SCRAPY_AVAILABLE = True
except ImportError:
    SCRAPY_AVAILABLE = False
    logger.warning("Scrapy not available - web crawling disabled")

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
        super(APTESSitemapSpider, self).__init__(*args, **kwargs)
        
        # Store output file path
        self.output_file = output_file
        
        if target_url:
            self.start_urls = [target_url]
            
            # Extract domain from URL
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            if domains:
                self.allowed_domains = domains
            else:
                self.allowed_domains = [domain]
        
        # Set up crawler rules
        self.rules = (
            Rule(LinkExtractor(allow_domains=self.allowed_domains), callback='parse_page', follow=True),
        )
        
        # Set maximum crawl depth
        self.max_depth = max_depth
        
        # Initialize sitemap
        self.sitemap = {}
        
        # Compile patterns for extracting forms, inputs, and scripts
        import re
        self.form_pattern = re.compile(r'<form[^>]*>.*?</form>', re.DOTALL)
        self.input_pattern = re.compile(r'<input[^>]*>', re.DOTALL)
        self.script_pattern = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL)
    
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
            if parsed.netloc in self.allowed_domains:
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
        
        # Return as Scrapy item
        item = SitemapItem()
        item.update(page_info)
        return item
    
    def closed(self, reason):
        """Called when crawler is closed"""
        logger.info(f"Crawler finished: {reason}")
        logger.info(f"Crawled {len(self.sitemap)} pages")


class JSONWriterPipeline:
    """Pipeline to write results to JSON file"""
    
    def __init__(self, output_file):
        self.output_file = output_file
        self.items = []
    
    @classmethod
    def from_crawler(cls, crawler):
        """Factory method called by Scrapy"""
        # Get output file from spider
        output_file = getattr(crawler.spider, 'output_file', None)
        if not output_file:
            # Fallback to a temporary file if not defined
            temp_dir = tempfile.mkdtemp(prefix="aptes_crawler_")
            output_file = os.path.join(temp_dir, "sitemap.json")
            logger.warning(f"Output file not defined, using temporary file: {output_file}")
        
        return cls(output_file=output_file)
    
    def process_item(self, item, spider):
        self.items.append(dict(item))
        return item
    
    def close_spider(self, spider):
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.items, f, indent=4)
            logger.info(f"Wrote {len(self.items)} items to {self.output_file}")
        except Exception as e:
            logger.error(f"Error writing to {self.output_file}: {str(e)}")


# Simpler approach without Scrapy's CrawlerProcess
def save_results_directly(results, output_file):
    """
    Save results directly to a JSON file
    
    Args:
        results (dict): Results to save
        output_file (str): File to save to
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        return False


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
        # Configure Scrapy settings
        settings = get_project_settings()
        settings.update({
            'USER_AGENT': 'APTES Crawler (+https://github.com/byteshell/aptes)',
            'ROBOTSTXT_OBEY': True,
            'CONCURRENT_REQUESTS': 16,
            'DOWNLOAD_DELAY': 0.5,
            'COOKIES_ENABLED': True,
            'ITEM_PIPELINES': {
                'lib.webcrawler.JSONWriterPipeline': 300,
            },
            'LOG_LEVEL': 'ERROR',
            'DEPTH_LIMIT': max_depth
        })
        
        # Create crawler process
        process = CrawlerProcess(settings)
        
        # Add spider to process with output file parameter
        process.crawl(
            APTESSitemapSpider, 
            target_url=target_url, 
            domains=domains, 
            max_depth=max_depth,
            output_file=output_file
        )
        
        # Run crawler
        process.start()
        
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
        
        # Save results directly in case the pipeline failed
        if len(sitemap) == 0 and len(sitemap_items) == 0:
            # Try a direct approach without Scrapy
            logger.info("No results from crawler, trying simple approach")
            # Just save the results structure with empty sitemap
            save_results_directly(results, output_file)
        
        return results
    
    except Exception as e:
        logger.error(f"Error in web crawl: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "error": str(e),
            "crawled_urls": 0,
            "sitemap": {}
        }


def convert_sitemap_to_json(sitemap):
    """
    Convert sitemap to JSON format for export
    
    Args:
        sitemap (dict): Sitemap structure
    
    Returns:
        dict: JSON-serializable sitemap
    """
    json_sitemap = {}
    
    for url, data in sitemap.items():
        # Create a copy of the data
        json_data = dict(data)
        
        # Remove any non-serializable objects
        if 'response' in json_data:
            del json_data['response']
        
        json_sitemap[url] = json_data
    
    return json_sitemap


def check_scrapy_installation():
    """
    Check if Scrapy is installed
    
    Returns:
        bool: True if Scrapy is installed, False otherwise
    """
    return SCRAPY_AVAILABLE


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
