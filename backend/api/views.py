""" The views.py file contains the views, which is the code executed when a client makes an HTTP request to the API. 
It contains the logic that processes the request and generates the response.

For example, when a client makes a request like:
    GET /actors/

the request arrives at urls.py, which forwards it to ActorViewSet. 
The latter retrieves the data from the database via the ORM, passes it to the serializer, and returns a JSON response to the client.

In addition to the standard CRUD endpoints for the models, 
this file also implements two custom endpoints that read a configuration file (sources.json) and allow searching for articles coming from RSS feeds.
"""

# json is used to read and write files in JSON format
import json

# Path allows you to manage file paths easily and independently of the operating system
from pathlib import Path

# Imports the feedparser library. This library allows you to automatically read an RSS feed
import feedparser

# HttpResponse is used to serve raw file content (JSON/Markdown) as a
# downloadable file, instead of a DRF Response (which always wraps
# the content in the API's standard JSON format)
from django.http import HttpResponse

# Imports the ViewSets from Django REST Framework. A ModelViewSet automatically implements all CRUD operations: Create, Read, Update, Delete, without having to write each function manually
from rest_framework import viewsets

# Imports the @api_view decorator. It is used to transform a regular Python function into a REST endpoint
from rest_framework.decorators import api_view
from rest_framework.response import Response

# # Imports all the database models. They will be used by the ViewSets to retrieve data
from .models import (
    TTP,
    Actor,
    ActorAlias,
    Campaign,
    Domain,
    FalsePositive,
    IOCExample,
)

# "Imports the serializers. Each ViewSet will use the corresponding serializer to convert Python objects to JSON
from .serializers import (
    ActorSerializer,
    CampaignSerializer,
    DomainSerializer,
    FalsePositiveSerializer,
    IOCExampleSerializer,
    TTPSerializer,
)


# Defines the ViewSet dedicated to Actors
# Thanks to ModelViewSet, all CRUD operations are automatically created
class ActorViewSet(viewsets.ModelViewSet):
    # Specifies which data the ViewSet manages
    # In this case: retrieves all Actors present in the database.
    queryset = Actor.objects.all()
    # Indicates which serializer to use
    # When an Actor is returned to the client, it will be converted to JSON via ActorSerializer
    serializer_class = ActorSerializer
    # Defines the fields on which searches can be performed
    search_fields = ["canonical_name", "country", "motivation"]

# Defines the ViewSet dedicated to Campaigns
# Automatically manages all CRUD operations related to campaigns
class CampaignViewSet(viewsets.ModelViewSet):
    # Retrieves all campaigns present in the database
    queryset = Campaign.objects.all()
    # Uses CampaignSerializer
    serializer_class = CampaignSerializer
    # Allows searching for campaigns by ID or description
    search_fields = ["campaign_id", "description"]

# Defines the ViewSet dedicated to TTPs
# Automatically manages all CRUD operations related to TTPs
class TTPViewSet(viewsets.ModelViewSet):
    # Retrieves all TTPs present in the database
    queryset = TTP.objects.all()
    # Uses TTPSerializer, converts objects to JSON
    serializer_class = TTPSerializer
    search_fields = ["ttp_code", "description"]

# Defines the ViewSet dedicated to Domains
# Automatically manages all CRUD operations related to Domains
class DomainViewSet(viewsets.ModelViewSet):
    queryset = Domain.objects.all()
    serializer_class = DomainSerializer
    search_fields = ["domain", "category"]

# Defines the ViewSet dedicated to IOCExamples
# Automatically manages all CRUD operations related to IOCExamples
class IOCExampleViewSet(viewsets.ModelViewSet):
    queryset = IOCExample.objects.all()
    serializer_class = IOCExampleSerializer
    search_fields = ["category", "value"]

# Defines the ViewSet dedicated to FalsePositives
# Automatically manages all CRUD operations related to FalsePositives
class FalsePositiveViewSet(viewsets.ModelViewSet):
    queryset = FalsePositive.objects.all()
    serializer_class = FalsePositiveSerializer
    search_fields = ["category", "value"]



# ENDPOINT FOR SEARCHING SOURCES
# Transforms the following function into a REST endpoint that accepts only HTTP GET requests
@api_view(['GET'])
# This function allows searching for articles within the RSS feeds configured in the project
# Search for articles from the RSS sources configured in knowledge/sources.json
def search_sources(request):
    # reads the q parameter passed in the URL
    # For example, in this case: query = "ransomware"
    query = request.GET.get('q', '')
    # Reads the list of requested sources
    sources_param = request.GET.get('sources', '')
    # Splits the comma-separated string into a Python list
    selected_sources = [s.strip() for s in sources_param.split(',') if s.strip()] if sources_param else []
    # Constructs the absolute path of the file:  knowledge/sources.json
    # which contains the configuration of the RSS sources
    sources_path = Path(__file__).parent.parent.parent / 'knowledge' / 'sources.json'
    # Verifies that the file exists
    # If missing: return Response(...) --> an HTTP 404 error is returned.
    if not sources_path.exists():
        return Response({
            'results': [],
            'total': 0,
            'error': f'File sources.json non trovato in {sources_path}'
        }, status=404)
    
    try:
        # Opens the JSON file
        with open(sources_path, 'r', encoding='utf-8') as f:
            # Converts the content of the file into a Python dictionary
            config = json.load(f)
    # If the file is corrupt or cannot be read, an HTTP 500 error is returned
    except (OSError, json.JSONDecodeError) as e:
        return Response({
            'results': [],
            'total': 0,
            'error': f'Errore nel leggere sources.json: {e}'
        }, status=500)
    # Retrieves the list of configured RSS feeds. If the field does not exist, it uses an empty list
    all_sources = config.get('narrative_feeds', [])
    # If the user has selected specific sources, only those are kept
    if selected_sources:
        all_sources = [s for s in all_sources if s['name'] in selected_sources]
    
    results = []
    for feed in all_sources:
        try:
            # Downloads and parses the RSS feed
            parsed = feedparser.parse(feed['url'])
            # Parses a maximum of the first 20 articles
            for entry in parsed.entries[:20]:
                title = entry.get('title', '')
                # If a search term was specified, all articles that do not contain it in the title are ignored
                if query and query.lower() not in title.lower():
                    continue
                # For each article found, the following are saved: source, title, publication date and URL
                results.append({
                    'source': feed['name'],
                    'title': title,
                    'published': entry.get('published', ''),
                    'url': entry.get('link', ''),
                })
        # If an RSS feed is unreachable or contains errors, a message is printed to the terminal, but processing continues with the other feeds
        except (AttributeError, KeyError, TypeError, ValueError) as e:
            print(f"Error fetching {feed['name']}: {e}")
    # Returns a JSON with: list of found articles and total number of results
    return Response({
        'results': results[:100],
        'total': len(results),
    })

# Accepts only GET requests
@api_view(['GET'])
# Simply returns the list of configured sources
def list_sources(request):
    """Returns just the configured source names, no live feed fetching."""
    sources_path = Path(__file__).parent.parent.parent / 'knowledge' / 'sources.json'
    # Reads sources.json
    with open(sources_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    # Extracts only the name of each source
    names = [s['name'] for s in config.get('narrative_feeds', [])]
    # Returns a JSON with the list of source names
    return Response({'sources': names})

# REPORTS PAGE ENDPOINTS
""" These endpoints power the Reports page: Step 1 raw extraction results per document, 
the final correlated/scored report, and file downloads of that final report. 
They only read files the pipeline has already produced on disk - none of them trigger a new pipeline run.

Absolute path to the data/ folder, built the same way sources_path is built above: 
this file lives in backend/api/, so we go up three
levels to reach the project root, then into data/ """
DATA_DIR = Path(__file__).parent.parent.parent / 'data'
EXTRACTED_DIR = DATA_DIR / 'extracted'
FINAL_REPORTS_DIR = DATA_DIR / 'final_reports'


@api_view(['GET'])
def list_extracted_reports(request):
    """Returns Step 1 extraction results for every processed document,
    read directly from data/extracted/*.json."""
    if not EXTRACTED_DIR.exists():
        return Response({'reports': [], 'total': 0})

    reports = []
    # Reads every extraction file produced by Step 1 so far
    for path in sorted(EXTRACTED_DIR.glob('*.json')):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                reports.append(json.load(f))
        # A single corrupted file should not break the whole listing
        except (OSError, json.JSONDecodeError) as e:
            print(f"Skipping invalid extraction file {path.name}: {e}")

    return Response({'reports': reports, 'total': len(reports)})


@api_view(['GET'])
def get_final_report(request):
    """Returns the latest Step 3 output: correlation results plus the
    computed threat score, as JSON for the Reports page to render."""
    report_path = FINAL_REPORTS_DIR / 'threat_report.json'

    if not report_path.exists():
        return Response(
            {'error': 'No final report available yet. Run the pipeline first.'},
            status=404,
        )

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return Response({'error': f'Could not read final report: {e}'}, status=500)

    return Response(data)


@api_view(['GET'])
def download_final_report(request):
    """Serves the latest final report as a downloadable file.
    Query param `format` selects json or md (default: json)."""
    file_format = request.GET.get('format', 'json')
    filename = 'threat_report.json' if file_format == 'json' else 'threat_report.md'
    report_path = FINAL_REPORTS_DIR / filename

    if not report_path.exists():
        return Response({'error': f'{filename} not found. Run the pipeline first.'}, status=404)

    content_type = 'application/json' if file_format == 'json' else 'text/markdown'
    with open(report_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Content-Disposition: attachment tells the browser to download the
    # file instead of trying to display it inline
    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


""" Generic, category-level explanations for indicator types that have no fixed per-value definition. 
Unlike an actor name or a TTP code, a single IP or hash is just raw data - 
there is nothing authoritative to say about *that specific value* without an external OSINT lookup,
which this project does not implement."""
INDICATOR_CATEGORY_EXPLANATIONS = {
    'ip': (
        "An IP address observed in connection with the reported activity, "
        "for example command-and-control traffic. IP addresses are often "
        "reused across unrelated campaigns and rotated frequently, so a "
        "single IP alone is weak evidence of attribution."
    ),
    'domains': (
        "A domain name associated with the reported activity, such as "
        "phishing or malware distribution. Domains registered for "
        "malicious use are frequently short-lived."
    ),
    'hashes': (
        "A cryptographic hash that uniquely fingerprints a specific file, "
        "most often a malware sample. Unlike an IP or a domain, a hash "
        "match is strong, unambiguous evidence: the same hash always "
        "refers to the exact same file content."
    ),
    'emails': (
        "An email address observed in the reported activity, for example "
        "as a threat actor contact point or as sender/recipient in a "
        "phishing attempt."
    ),
    'urls': (
        "A specific web address linked to malicious activity, such as a "
        "phishing page or a malware download link."
    ),
    'suspicious_files': (
        "A file name flagged as part of the reported activity. Unlike a "
        "hash, a file name alone is not a reliable identifier, since it "
        "can be freely renamed."
    ),
}

""" Maps the plural field names used in Step 1's extraction schema (e.g. "hashes", "domains") 
to the singular category values used by the IOCExample model's CATEGORY_CHOICES (e.g. "hash", "domain") -
the two schemas were defined independently and don't match exactly """
EXTRACTION_TO_IOC_CATEGORY = {
    'ip': 'ip',
    'domains': 'domain',
    'hashes': 'hash',
    'emails': 'email',
    'urls': 'url',
    'suspicious_files': 'suspicious_file',
}


@api_view(['GET'])
def explain_entity(request):
    """Returns an explanation for a specific extracted entity.

    Lookup strategy depends on the category:
    - actor: looked up by canonical name, falling back to known aliases
    - ttp: looked up in the local TTP table, plus a link to the official
      MITRE ATT&CK page
    - cve: not implemented yet - an external NVD reference link is
      returned instead of a live lookup
    - ip / domains / hashes / emails / urls / suspicious_files: checked
      against curated, approved IOCExample entries first; if none
      exists, a generic explanation of the category is returned instead
      of a per-value definition
    """
    category = request.GET.get('category', '')
    value = request.GET.get('value', '')

    if not category or not value:
        return Response({'error': 'Both category and value query params are required.'}, status=400)

    if category == 'actor':
        actor = Actor.objects.filter(canonical_name__iexact=value).first()
        if not actor:
            # value might be a known alias (e.g. "Cozy Bear") rather
            # than the canonical name (e.g. "APT29")
            alias_match = ActorAlias.objects.filter(alias__iexact=value).select_related('actor').first()
            actor = alias_match.actor if alias_match else None

        if actor:
            return Response({
                'found': True,
                'category': category,
                'value': value,
                'canonical_name': actor.canonical_name,
                'country': actor.country,
                'motivation': actor.motivation,
                'notes': actor.notes,
                'aliases': list(actor.aliases.values_list('alias', flat=True)),
            })
        return Response({'found': False, 'category': category, 'value': value})

    if category == 'ttp':
        ttp = TTP.objects.filter(ttp_code__iexact=value).first()
        if ttp:
            return Response({
                'found': True,
                'category': category,
                'value': value,
                'ttp_code': ttp.ttp_code,
                'description': ttp.description,
                'mitre_url': f'https://attack.mitre.org/techniques/{value.replace(".", "/")}/',
            })
        return Response({'found': False, 'category': category, 'value': value})

    if category == 'cve':
        return Response({
            'found': False,
            'category': category,
            'value': value,
            'note': 'Live CVE lookup is not implemented yet. Planned: query the NVD API.',
            'external_url': f'https://nvd.nist.gov/vuln/detail/{value}',
        })

    if category in INDICATOR_CATEGORY_EXPLANATIONS:
        ioc_category = EXTRACTION_TO_IOC_CATEGORY.get(category)
        # Prefer a curated, human-approved example over the generic
        # category text, when one exists for this exact value
        curated = IOCExample.objects.filter(
            category=ioc_category,
            value__iexact=value,
            approved=True,
        ).first()

        if curated:
            return Response({
                'found': True,
                'category': category,
                'value': value,
                'curated_context': curated.context,
                'source_article': curated.source_article,
            })

        return Response({
            'found': True,
            'category': category,
            'value': value,
            'generic_explanation': INDICATOR_CATEGORY_EXPLANATIONS[category],
            'note': (
                'This category has no per-value definition - the '
                'explanation describes what this type of indicator '
                'represents in general, not this specific value.'
            ),
        })

    return Response({'error': f'Unknown category: {category}'}, status=400)