"""API URL configuration.

The urls.py file defines the API endpoints, which are the web addresses (URLs) through which a client can communicate with the backend.

models represent the database;
serializers translate data into JSON and vice versa;
views contain the application logic;
urls.py is the map that tells which entry point to use to reach each service.

For example, when a client sends an HTTP request such as:
    GET /actors/
Django consults this file to figure out which function or class should handle the request.

In other words, urls.py connects each URL to its corresponding view, 
which will process the request and generate the response"""

# path - Used to define a new path (URL)
# include - Used to include other groups of URLs
from django.urls import include, path

# Imports the DefaultRouter from Django REST Framework
from rest_framework.routers import DefaultRouter

# Imports all the views defined in the views.py file
from .views import (
    # The first are ViewSets, which are classes that automatically handle CRUD operations: Create, Read, Update, Delete.
    ActorViewSet,
    CampaignViewSet,
    DomainViewSet,
    FalsePositiveViewSet,
    IOCExampleViewSet,
    TTPViewSet,
    # The last are function-based views, which are simpler and handle specific tasks
    # Are simple functions: list_sources and search_sources. They implement custom functionalities
    list_sources,
    search_sources,
)

# Creates a router, which is a component that automatically generates the URLs for the ViewSets
router = DefaultRouter()
# Registers the ViewSet dedicated to actors. From this moment on, the router automatically creates all endpoints related to Actors
# For example: GET /actors/ returns all actors
# GET /actors/5/ returns the actor with ID 5
router.register(r"actors", ActorViewSet)
# Registers the endpoints dedicated to campaigns. URLs such as /campaigns/ will be available
router.register(r"campaigns", CampaignViewSet)
# Registers the endpoints for TTPs
router.register(r"ttps", TTPViewSet)
# Registers the endpoints for domains, IOC examples, and false positives
router.register(r"domains", DomainViewSet)
router.register(r"ioc-examples", IOCExampleViewSet)
router.register(r"false-positives", FalsePositiveViewSet)

# urlpatterns is a list containing all the URLs managed by this application
# Each element represents a path that Django will be able to recognize
urlpatterns = [
    # Includes all the URLs automatically created by the router
    # Thanks to this single line, all previously registered endpoints become available
    # Without this instruction, the router would exist, but Django would not use it.
    path("", include(router.urls)),
    # Defines a custom endpoint
    # Defines the path for the search_sources function, which will be accessible at /sources/search
    path("sources/search", search_sources, name="search_sources"),
    # Defines a custom endpoint
    # Defines the path for the list_sources function, which will be accessible at /sources/list
    path("sources/list", list_sources, name="list_sources"),
]