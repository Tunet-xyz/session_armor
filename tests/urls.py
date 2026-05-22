from django.urls import path
from django.http import HttpResponse


def ok_view(request):
    return HttpResponse("OK")


urlpatterns = [
    path('', ok_view),
]
