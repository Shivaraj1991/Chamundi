from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.api_login, name="api_login"),
    path("users/<int:user_id>/", views.api_get_user, name="api_get_user"),
    path("users/<int:user_id>/update/", views.api_update_user, name="api_update_user"),
    path("orders/<int:order_id>/", views.api_get_order, name="api_get_order"),
    path("products/", views.api_create_product, name="api_create_product"),
    path("products/search/", views.api_search_products, name="api_search_products"),
    path("admin/stats/", views.api_admin_stats, name="api_admin_stats"),
    path("debug/", views.api_debug_info, name="api_debug_info"),
]
