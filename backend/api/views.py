from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import (
    Actor,
    Campaign,
    TTP,
    Domain,
    IOCExample,
    FalsePositive,
)
from .serializers import (
    ActorSerializer,
    CampaignSerializer,
    TTPSerializer,
    DomainSerializer,
    IOCExampleSerializer,
    FalsePositiveSerializer,
)


class ActorViewSet(viewsets.ModelViewSet):
    queryset = Actor.objects.all()
    serializer_class = ActorSerializer
    search_fields = ["canonical_name", "country", "motivation"]


class CampaignViewSet(viewsets.ModelViewSet):
    queryset = Campaign.objects.all()
    serializer_class = CampaignSerializer
    search_fields = ["campaign_id", "description"]


class TTPViewSet(viewsets.ModelViewSet):
    queryset = TTP.objects.all()
    serializer_class = TTPSerializer
    search_fields = ["ttp_code", "description"]


class DomainViewSet(viewsets.ModelViewSet):
    queryset = Domain.objects.all()
    serializer_class = DomainSerializer
    search_fields = ["domain", "category"]


class IOCExampleViewSet(viewsets.ModelViewSet):
    queryset = IOCExample.objects.all()
    serializer_class = IOCExampleSerializer
    search_fields = ["category", "value"]


class FalsePositiveViewSet(viewsets.ModelViewSet):
    queryset = FalsePositive.objects.all()
    serializer_class = FalsePositiveSerializer
    search_fields = ["category", "value"]