"""DRF serializers for threat_intel models."""

from rest_framework import serializers

from .models import (
    TTP,
    Actor,
    ActorAlias,
    Campaign,
    Domain,
    FalsePositive,
    IOCExample,
)


class ActorAliasSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActorAlias
        fields = ["id", "alias"]


class ActorSerializer(serializers.ModelSerializer):
    aliases = ActorAliasSerializer(many=True, read_only=True)

    class Meta:
        model = Actor
        fields = ["id", "canonical_name", "country", "motivation", "notes", "first_seen", "aliases"]


class CampaignSerializer(serializers.ModelSerializer):
    class Meta:
        model = Campaign
        fields = ["id", "campaign_id", "first_seen", "last_seen", "description"]


class TTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = TTP
        fields = ["id", "ttp_code", "is_generic", "description"]


class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = ["id", "domain", "description", "category", "notes", "created_at"]


class IOCExampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOCExample
        fields = ["id", "category", "value", "context", "source_article", "confidence", "created_at", "approved"]


class FalsePositiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = FalsePositive
        fields = ["id", "category", "value", "context", "source_article", "created_at", "approved"]