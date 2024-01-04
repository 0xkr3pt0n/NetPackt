
from django.contrib import admin
from django.urls import path,include

urlpatterns = [
    path('', include('core.urls')),
    path('', include('netscan.urls')),
    path('', include('host_Discovery.urls')),
    path('admin/', admin.site.urls),
    
]

