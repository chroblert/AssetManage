from django.urls import path
from assets import views


app_name = 'assets'


urlpatterns = [
    # path('report/', views.report, name='report'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('index/', views.index, name='index'),
    path('displayport/',views.displayport,name='displayport'),
    path('', views.dashboard),
]