from django.urls import path
from baseline import views

app_name = 'baseline'


urlpatterns = [
    # path('report/', views.report, name='report'),
    path('show/', views.show, name="show"),
]