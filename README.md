# APTES - Advanced Penetration Testing and Exploitation Suite

A comprehensive automated security assessment framework for reconnaissance, pre-exploitation, exploitation, and post-exploitation phases.

## New Features

### Sequential Phase Execution

APTES now supports running multiple phases in sequence with results automatically passed between phases:

```bash
# Run reconnaissance followed by pre-exploitation
python -m aptes example.com -p recon preexploit

# Run the full assessment pipeline
python -m aptes example.com -p all

# Run specific phases in custom order
python -m aptes example.com -p recon preexploit exploit
```

When multiple phases are executed, the results from each phase are passed to subsequent phases automatically. The complete results from all phases are saved in a single JSON file at the end of execution.

### Web Crawling with Scrapy

APTES now includes web crawling capabilities using Scrapy to generate a comprehensive sitemap of target websites:

```bash
# Run reconnaissance with web crawling
python -m aptes example.com -p recon --crawl-web

# Customize crawl depth (default is 2)
python -m aptes example.com -p recon --crawl-web --crawl-depth 3
```

The web crawler:
- Maps all pages, links, and forms on target websites
- Identifies potential vulnerable URLs with parameters
- Generates a detailed sitemap stored in the results
- Creates JSON sitemap files in the output directory

## Installation

To use the new web crawling features, install APTES with the webcrawl extra:

```bash
# Basic installation
pip install .

# Installation with web crawling support
pip install .[webcrawl]

# Full installation with all features
pip install .[full]
```

## Usage Examples

### Basic Sequence

```bash
# Run reconnaissance and pre-exploitation phases in sequence
python -m aptes example.com -p recon preexploit --output-dir my_assessment
```

### Complete Assessment with Web Crawling

```bash
# Run all phases with web crawling
python -m aptes example.com -p all --crawl-web --crawl-depth 3 --output-dir full_assessment
```

### Custom Phase Selection with Filtering

```bash
# Run selected phases focusing on high-risk issues
python -m aptes example.com -p recon preexploit --filter high --crawl-web
```

## Output

When running multiple phases, APTES creates:
- Individual phase reports in the specified format (optional)
- A comprehensive JSON file containing all results from all phases
- Sitemap JSON files in the `output_dir/sitemaps/` directory (when web crawling is enabled)
