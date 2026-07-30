"""DRF serializers for threat_intel models.

If models.py describes how the data is structured in the database and the ORM allows you to work with it in Python, 
serializers are responsible for transforming this data into a format that can be sent over a network, typically JSON, and vice versa.

In practice, they act as a translator between the backend and the client (browser, mobile app, React frontend, etc.).
For example, a Python object like:
    Actor(
        id=1,
        canonical_name="APT29",
        country="Russia"
    )

is automatically transformed into:
    {
        "id": 1,
        "canonical_name": "APT29",
        "country": "Russia"
    }
Conversely, when the client sends JSON to the server (for example, to create a new Actor), 
the serializer verifies that the data is valid and converts it back into a Python object that Django can save to the database"""

# Imports the Django REST Framework serializers module
# With this module, we can create classes that automatically convert Python objects to JSON and vice versa
from rest_framework import serializers

# Imports all the models defined in models.py
# Each serializer will be associated with one of these models
from .models import (
    TTP,
    Actor,
    ActorAlias,
    Campaign,
    Domain,
    FalsePositive,
    IOCExample,
)


# Defines the serializer for the ActorAlias model
class ActorAliasSerializer(serializers.ModelSerializer):
    # This class is used to configure the serializer
    class Meta:
        # This serializer works on the ActorAlias model
        model = ActorAlias
        # Specifies which fields should appear in the JSON
        fields = ["id", "alias"]

# Serializer for the Actor model
class ActorSerializer(serializers.ModelSerializer):
    # When returning an Actor, also return all its aliases
    # Multiple aliases exist. In fact, an actor can have: Cozy Bear, The Dukes, Midnight Blizzard, all associated with the same Actor
    # Aliases are read-only. If JSON with aliases arrives, this serializer will not attempt to create or modify them
    aliases = ActorAliasSerializer(many=True, read_only=True)

    class Meta:
        model = Actor
        # These are all the fields that will appear in the JSON
        fields = ["id", "canonical_name", "country", "motivation", "notes", "first_seen", "aliases"]

# Serializer for the Campaign model
class CampaignSerializer(serializers.ModelSerializer):
    class Meta:
        model = Campaign
        # These are the fields that will be converted to JSON
        fields = ["id", "campaign_id", "first_seen", "last_seen", "description"]

# Serializer for the TTP model
class TTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = TTP
        # These are the fields that will be converted to JSON
        # Returns the MITRE code, if it is generic, and the description
        fields = ["id", "ttp_code", "is_generic", "description"]

# Serializer for the Domain model
class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        # These are the fields that will be converted to JSON
        fields = ["id", "domain", "description", "category", "notes", "created_at"]

# Serializer for the IOCExample model
class IOCExampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOCExample
        # These are the fields that will be converted to JSON
        fields = ["id", "category", "value", "context", "source_article", "confidence", "created_at", "approved"]

# Serializer for the FalsePositive model
class FalsePositiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = FalsePositive
        # These are the fields that will be converted to JSON
        fields = ["id", "category", "value", "context", "source_article", "created_at", "approved"]