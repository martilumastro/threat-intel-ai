"""API URL configuration."""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    ActorViewSet,
    CampaignViewSet,
    TTPViewSet,
    DomainViewSet,
    IOCExampleViewSet,
    FalsePositiveViewSet,
)

router = DefaultRouter()
router.register(r"actors", ActorViewSet)
router.register(r"campaigns", CampaignViewSet)
router.register(r"ttps", TTPViewSet)
router.register(r"domains", DomainViewSet)
router.register(r"ioc-examples", IOCExampleViewSet)
router.register(r"false-positives", FalsePositiveViewSet)

urlpatterns = [
    path("", include(router.urls)),
]