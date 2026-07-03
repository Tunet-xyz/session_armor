from django.http import HttpResponse
from django.urls import path


def ok_view(request):
    return HttpResponse("OK")


urlpatterns = [
    path("", ok_view),
]
