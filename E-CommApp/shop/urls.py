from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("search/", views.search, name="search"),
    path("product/<int:pk>/", views.product_detail, name="product_detail"),

    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("reset-password/", views.password_reset_request, name="password_reset_request"),
    path("reset-password/confirm/", views.password_reset_confirm, name="password_reset_confirm"),

    path("profile/<int:user_id>/", views.profile_view, name="profile"),
    path("profile/avatar/upload/", views.upload_avatar, name="upload_avatar"),
    path("files/download/", views.download_file, name="download_file"),

    path("cart/", views.cart_view, name="cart_view"),
    path("cart/add/<int:pk>/", views.add_to_cart, name="add_to_cart"),
    path("cart/remove/<int:pk>/", views.remove_from_cart, name="remove_from_cart"),
    path("checkout/", views.checkout, name="checkout"),
    path("orders/", views.order_list, name="order_list"),
    path("orders/<int:order_id>/", views.order_detail, name="order_detail"),

    path("coupon/", views.apply_coupon, name="apply_coupon"),
    path("track-shipment/", views.track_shipment, name="track_shipment"),
    path("email-preview/", views.email_preview, name="email_preview"),
    path("import/xml/", views.import_products_xml, name="import_products_xml"),
    path("import/image-url/", views.import_image_url, name="import_image_url"),
]
