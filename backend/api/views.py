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

# Imports the ViewSets from Django REST Framework. A ModelViewSet automatically implements all CRUD operations: Create, Read, Update, Delete, without having to write each function manually
from rest_framework import viewsets

# Imports the @api_view decorator. It is used to transform a regular Python function into a REST endpoint
from rest_framework.decorators import api_view
from rest_framework.response import Response

# # Imports all the database models. They will be used by the ViewSets to retrieve data
from .models import (
    TTP,
    Actor,
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