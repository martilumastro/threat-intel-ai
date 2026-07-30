from django.db import models

# Create your models here.
"""Django models mirroring the threat_intel.db schema.

models.py: the representation of the database in Python code

The models.py file is what the programmer writes and modifies. This is where you define the Python classes that represent the database tables.
For example:
    class Actor(models.Model):
        canonical_name = models.CharField(max_length=200, unique=True)

This does not directly create a table in the database; 
instead, it defines a Python model that Django uses through the ORM (Object-Relational Mapper).

Thanks to the ORM, you can work with objects instead of writing SQL queries. 
For example:
    actor = Actor.objects.create(canonical_name="APT29")

Django automatically translates this instruction into an SQL query similar to:
    INSERT INTO actor (canonical_name) VALUES ('APT29');

models.py describes the data model that the Python code will use daily via the ORM. 
It serves the backend to interact with the database through the ORM.

0001_initial.py, on the other hand, is used only when it is necessary to create or modify the database structure. 
Once the migration has been applied, the file remains as a historical record of the changes made to the database."""


class Actor(models.Model):
    canonical_name = models.CharField(max_length=200, unique=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    motivation = models.CharField(max_length=200, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    first_seen = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.canonical_name

    class Meta:
        verbose_name_plural = "Actors"


class ActorAlias(models.Model):
    actor = models.ForeignKey(Actor, on_delete=models.CASCADE, related_name="aliases")
    alias = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.alias

    class Meta:
        verbose_name_plural = "Actor aliases"


class Campaign(models.Model):
    campaign_id = models.CharField(max_length=100, unique=True)
    first_seen = models.DateField(blank=True, null=True)
    last_seen = models.DateField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.campaign_id


class TTP(models.Model):
    ttp_code = models.CharField(max_length=20, unique=True)
    is_generic = models.BooleanField(default=False)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.ttp_code


class CampaignActor(models.Model):
    campaign = models.ForeignKey(Campaign, on_delete=models.CASCADE)
    actor = models.ForeignKey(Actor, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("campaign", "actor")


class CampaignTTP(models.Model):
    campaign = models.ForeignKey(Campaign, on_delete=models.CASCADE)
    ttp = models.ForeignKey(TTP, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("campaign", "ttp")


class Domain(models.Model):
    domain = models.CharField(max_length=253, unique=True)
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=50, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain


class ActorDomain(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    actor = models.ForeignKey(Actor, on_delete=models.CASCADE)
    frequency = models.IntegerField(default=1)

    class Meta:
        unique_together = ("domain", "actor")


class IOCExample(models.Model):
    CATEGORY_CHOICES = [
        ("ip", "IP"),
        ("domain", "Domain"),
        ("hash", "Hash"),
        ("actor", "Actor"),
        ("ttp", "TTP"),
        ("cve", "CVE"),
        ("url", "URL"),
        ("suspicious_file", "Suspicious File"),
    ]
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    value = models.CharField(max_length=500)
    context = models.TextField(blank=True, null=True)
    source_article = models.CharField(max_length=500, blank=True, null=True)
    confidence = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)

    class Meta:
        unique_together = ("category", "value")


class FalsePositive(models.Model):
    CATEGORY_CHOICES = [
        ("actor", "Actor"),
        ("domain", "Domain"),
        ("ip", "IP"),
        ("hash", "Hash"),
        ("email", "Email"),
        ("ttp", "TTP"),
        ("cve", "CVE"),
        ("url", "URL"),
        ("suspicious_file", "Suspicious File"),
    ]
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    value = models.CharField(max_length=500)
    context = models.TextField(blank=True, null=True)
    source_article = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)

    class Meta:
        unique_together = ("category", "value")