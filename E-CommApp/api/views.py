"""
VulnShop JSON API.

*** INTENTIONALLY VULNERABLE - see README.md for the full catalog. ***
This API deliberately reproduces the OWASP API Security Top 10 patterns
(BOLA, broken authentication, excessive data exposure, mass assignment,
broken function-level authorization, unrestricted resource consumption,
and injection) so they can be tested with a plain HTTP client (curl,
Postman, Burp).
"""

import hashlib
import json

from django.contrib.auth.models import User
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from shop.models import Order, Product, UserProfile


def _body(request):
    try:
        return json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return {}


def _user_dict(user):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    # VULNERABILITY #34 - Excessive Data Exposure (API3:2023). The API
    # returns the raw password hash, full credit card number, and the
    # internal role/api_key fields instead of a filtered, minimal
    # representation - it's relying on the client to discard fields it
    # doesn't need.
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "password_hash": user.password,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
        "credit_card_number": profile.credit_card_number,
        "api_key": profile.api_key,
        "role": profile.role,
    }


@csrf_exempt
def api_login(request):
    # VULNERABILITY #37 - Broken Authentication (API2:2023): no rate
    # limiting/lockout on login attempts, so credentials (hashed with the
    # weak MD5 scheme from shop/views.register) can be brute-forced freely.
    data = _body(request)
    username = data.get("username")
    password = data.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()
    user = User.objects.filter(username=username, password=password_hash).first()
    if not user:
        return JsonResponse({"error": "invalid credentials"}, status=401)
    return JsonResponse(_user_dict(user))


def api_get_user(request, user_id):
    # VULNERABILITY #29 - Broken Object Level Authorization / BOLA
    # (API1:2023). Any caller can fetch any user's record by id, with no
    # check that the requester owns / is authorized to see it.
    user = User.objects.filter(pk=user_id).first()
    if not user:
        return JsonResponse({"error": "not found"}, status=404)
    return JsonResponse(_user_dict(user))


@csrf_exempt
def api_update_user(request, user_id):
    # VULNERABILITY #31 - Mass Assignment (API3:2023) + Broken Function
    # Level Authorization (API5:2023). The entire JSON body is applied to
    # the user/profile via setattr with no field allow-list and no
    # authorization check, so any caller can PATCH is_staff, is_superuser,
    # or role on ANY account - trivial privilege escalation:
    #   PATCH /api/users/2/  {"is_staff": true, "is_superuser": true}
    user = User.objects.filter(pk=user_id).first()
    if not user:
        return JsonResponse({"error": "not found"}, status=404)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    data = _body(request)
    for field, value in data.items():
        if hasattr(user, field):
            setattr(user, field, value)
        elif hasattr(profile, field):
            setattr(profile, field, value)
    user.save()
    profile.save()
    return JsonResponse(_user_dict(user))


def api_get_order(request, order_id):
    # VULNERABILITY #30 - BOLA (API1:2023). No ownership check against the
    # caller, so any order (address, total, status) is readable by id.
    order = Order.objects.filter(pk=order_id).first()
    if not order:
        return JsonResponse({"error": "not found"}, status=404)
    return JsonResponse(
        {
            "id": order.id,
            "user_id": order.user_id,
            "total": str(order.total),
            "shipping_address": order.shipping_address,
            "status": order.status,
        }
    )


@csrf_exempt
def api_create_product(request):
    # VULNERABILITY #32 - Broken Function Level Authorization (API5:2023).
    # Creating/pricing a product has NO authentication check whatsoever -
    # any anonymous caller can add products (or, with api_update_user,
    # rewrite prices on existing ones).
    data = _body(request)
    product = Product.objects.create(
        name=data.get("name", ""),
        description=data.get("description", ""),
        price=data.get("price", 0),
        stock=data.get("stock", 0),
    )
    return JsonResponse({"id": product.id})


def api_search_products(request):
    q = request.GET.get("q", "")
    limit = request.GET.get("limit", "50")
    with connection.cursor() as cursor:
        # VULNERABILITY #35 - SQL Injection (API8:2023 - Security
        # Misconfiguration / Injection), in both the search term and the
        # LIMIT clause.
        # VULNERABILITY #36 - Unrestricted Resource Consumption (API4:2023):
        # `limit` is attacker-controlled with no upper bound, no pagination,
        # and no query cost limit.
        query = "SELECT id, name, price FROM shop_product WHERE name LIKE '%%%s%%' LIMIT %s" % (q, limit)
        cursor.execute(query)
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})


def api_admin_stats(request):
    # VULNERABILITY #33 - Broken Function Level Authorization (API5:2023).
    # "Admin" access is gated on a client-supplied query parameter instead
    # of request.user.is_staff, so anyone can add ?is_admin=true.
    if request.GET.get("is_admin") == "true":
        return JsonResponse(
            {
                "total_users": User.objects.count(),
                "total_orders": Order.objects.count(),
                "all_emails": list(User.objects.values_list("email", flat=True)),
            }
        )
    return JsonResponse({"error": "forbidden"}, status=403)


def api_debug_info(request):
    # VULNERABILITY #38 - Security Misconfiguration / Sensitive Data
    # Exposure (API8:2023). A debug endpoint left reachable in "production"
    # leaks the Django SECRET_KEY and other settings.
    from django.conf import settings

    return JsonResponse(
        {
            "debug": settings.DEBUG,
            "secret_key": settings.SECRET_KEY,
            "payment_gateway_api_secret": settings.PAYMENT_GATEWAY_API_SECRET,
            "allowed_hosts": settings.ALLOWED_HOSTS,
            "installed_apps": settings.INSTALLED_APPS,
        }
    )
