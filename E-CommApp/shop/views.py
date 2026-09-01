"""
VulnShop views.

*** INTENTIONALLY VULNERABLE - see README.md for the full catalog. ***
Every VULNERABILITY comment below corresponds to a numbered entry in
README.md so findings can be cross-referenced quickly during a
training/CTF exercise.
"""

import hashlib
import os
import random
import subprocess

import requests
from django.conf import settings
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import connection
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template import Context, Template
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .cart import get_cart, save_cart
from .models import Coupon, Order, OrderItem, Product, Review, UserProfile

try:
    from lxml import etree
except ImportError:  # pragma: no cover
    etree = None


# ---------------------------------------------------------------------------
# Catalog / search
# ---------------------------------------------------------------------------

def _decorate_for_display(product):
    """Attach cosmetic-only rating/discount figures for the storefront UI.

    These are derived deterministically from the product id purely so the
    catalog has ratings/MRP/discount badges to render - they are not stored
    fields and carry no security meaning.
    """
    price = float(product.price)
    discount = (product.id * 13) % 40 + 5
    product.demo_rating = (product.id % 5) + 1
    product.demo_reviews = (product.id * 37) % 900 + 15
    product.demo_discount = discount
    product.demo_mrp = round(price / (1 - discount / 100.0), 2)
    return product


def home(request):
    products = [_decorate_for_display(p) for p in Product.objects.all()]
    return render(request, "shop/home.html", {"products": products})


def product_detail(request, pk):
    product = get_object_or_404(Product, pk=pk)
    _decorate_for_display(product)
    if request.method == "POST" and request.user.is_authenticated:
        # VULNERABILITY #4 - Stored XSS: the review comment is stored as-is
        # and rendered with `|safe` in product_detail.html.
        Review.objects.create(
            product=product,
            user=request.user,
            comment=request.POST.get("comment", ""),
            rating=int(request.POST.get("rating", 5) or 5),
        )
        return redirect("product_detail", pk=pk)
    return render(request, "shop/product_detail.html", {"product": product, "reviews": product.reviews.all()})


def search(request):
    q = request.GET.get("q", "")
    results = []
    if q:
        with connection.cursor() as cursor:
            # VULNERABILITY #1 - SQL Injection (OWASP A03:2021). Raw string
            # formatting instead of a parameterized query. Try:
            #   ?q=' UNION SELECT id,username,password,1 FROM auth_user --
            query = "SELECT id, name, description, price FROM shop_product WHERE name LIKE '%%%s%%'" % q
            cursor.execute(query)
            results = cursor.fetchall()
    # VULNERABILITY #3 - Reflected XSS: `q` is echoed back into the page with
    # `|safe` in search_results.html. Try: ?q=<script>alert(document.cookie)</script>
    return render(request, "shop/search_results.html", {"query": q, "results": results})


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def register(request):
    error = None
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        email = request.POST.get("email", "")
        if User.objects.filter(username=username).exists():
            error = "Username already taken"
        else:
            user = User(username=username, email=email)
            # VULNERABILITY #5 - Insecure Cryptographic Storage (OWASP
            # A02:2021). Passwords are hashed with unsalted MD5 instead of
            # Django's set_password()/PBKDF2 hasher, and no password policy
            # is enforced (settings.AUTH_PASSWORD_VALIDATORS = []).
            user.password = hashlib.md5(password.encode()).hexdigest()
            user.save()
            # VULNERABILITY #6 - predictable/sequential API key (just the
            # zero-padded numeric user id) instead of a random token.
            api_key = str(user.id).zfill(8)
            UserProfile.objects.create(user=user, api_key=api_key)
            auth_login(request, user)
            return redirect("home")
    return render(request, "shop/register.html", {"error": error})


def login_view(request):
    error = None
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        password_hash = hashlib.md5(password.encode()).hexdigest()
        with connection.cursor() as cursor:
            # VULNERABILITY #2 - SQL Injection auth bypass (OWASP A03:2021).
            # Try username: admin' -- and any password.
            query = "SELECT id FROM auth_user WHERE username = '%s' AND password = '%s'" % (
                username,
                password_hash,
            )
            cursor.execute(query)
            row = cursor.fetchone()
        if row:
            user = User.objects.get(pk=row[0])
            auth_login(request, user)
            next_url = request.POST.get("next") or request.GET.get("next")
            if next_url:
                # VULNERABILITY #22 - Open Redirect (OWASP A01:2021). No
                # validation that `next_url` is a safe, same-site path, e.g.
                # ?next=https://evil.example/phish
                return redirect(next_url)
            return redirect("home")
        error = "Invalid credentials"
    return render(request, "shop/login.html", {"error": error})


def logout_view(request):
    auth_logout(request)
    return redirect("home")


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

def password_reset_request(request):
    token = None
    note = None
    if request.method == "POST":
        username = request.POST.get("username", "")
        user = User.objects.filter(username=username).first()
        if user:
            # VULNERABILITY #20 - Broken Password Reset (OWASP A07:2021). A
            # short, non-cryptographic, predictable 6-digit token
            # (random.randint is not a CSPRNG) with no expiry enforcement.
            token = str(random.randint(100000, 999999))
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.reset_token = token
            profile.reset_token_created = timezone.now()
            profile.save()
            # VULNERABILITY #21 - Host Header Injection. In a real deployment
            # this link would be emailed to the user; building it from
            # request.get_host() (attacker-controllable when ALLOWED_HOSTS
            # is "*") lets an attacker poison the reset link's domain.
            reset_link = f"http://{request.get_host()}/reset-password/confirm/"
            note = (
                "Demo mode: no email backend is configured, so the token is "
                f"shown here directly instead of being emailed. Reset link: {reset_link}"
            )
        else:
            note = "If that account exists, a reset token has been generated."
    return render(request, "shop/password_reset.html", {"token": token, "note": note})


def password_reset_confirm(request):
    error = None
    success = None
    if request.method == "POST":
        username = request.POST.get("username", "")
        token = request.POST.get("token", "")
        new_password = request.POST.get("new_password", "")
        user = User.objects.filter(username=username).first()
        profile = getattr(user, "profile", None) if user else None
        # VULNERABILITY #20 (cont.) - no rate limiting on attempts and no
        # check that reset_token_created is within a short expiry window,
        # so the 6-digit token is brute-forceable (only ~1e6 values).
        if profile and profile.reset_token and profile.reset_token == token:
            user.password = hashlib.md5(new_password.encode()).hexdigest()
            user.save()
            profile.reset_token = ""
            profile.save()
            success = "Password reset. You can now log in."
        else:
            error = "Invalid token"
    return render(request, "shop/password_reset_confirm.html", {"error": error, "success": success})


# ---------------------------------------------------------------------------
# Profile (IDOR)
# ---------------------------------------------------------------------------

@login_required
def profile_view(request, user_id):
    # VULNERABILITY #7 - IDOR / Broken Access Control (OWASP A01:2021). Any
    # authenticated user can view AND edit any other user's profile just by
    # changing user_id in the URL - there is no check that user_id ==
    # request.user.id.
    target_user = get_object_or_404(User, pk=user_id)
    profile, _ = UserProfile.objects.get_or_create(user=target_user)
    if request.method == "POST":
        profile.bio = request.POST.get("bio", profile.bio)
        profile.phone = request.POST.get("phone", profile.phone)
        profile.credit_card_number = request.POST.get("credit_card_number", profile.credit_card_number)
        profile.save()
    return render(request, "shop/profile.html", {"target_user": target_user, "profile": profile})


@login_required
def upload_avatar(request):
    if request.method == "POST" and request.FILES.get("avatar"):
        f = request.FILES["avatar"]
        # VULNERABILITY #12 - Unrestricted/Insecure File Upload (OWASP
        # A04:2021). No allow-list on extension/content-type, no size
        # limit, and the client-supplied filename is trusted verbatim.
        # VULNERABILITY #13 - Path Traversal via the same filename, e.g.
        # "../../../vulnshop/settings.py" as the upload name.
        dest_path = os.path.join(settings.MEDIA_ROOT, "avatars", f.name)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "wb+") as out:
            for chunk in f.chunks():
                out.write(chunk)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.avatar = f"avatars/{f.name}"
        profile.save()
    return render(request, "shop/upload_avatar.html")


def download_file(request):
    filename = request.GET.get("file", "")
    # VULNERABILITY #14 - Path Traversal / Arbitrary File Read (OWASP
    # A01:2021). Try: ?file=../../vulnshop/settings.py
    path = os.path.join(settings.MEDIA_ROOT, filename)
    return FileResponse(open(path, "rb"))


# ---------------------------------------------------------------------------
# Cart / checkout
# ---------------------------------------------------------------------------

def cart_view(request):
    cart = get_cart(request)
    total = sum(item["price"] * item["qty"] for item in cart.values())
    return render(request, "shop/cart.html", {"cart": cart, "total": total})


def add_to_cart(request, pk):
    product = get_object_or_404(Product, pk=pk)
    cart = get_cart(request)
    item = cart.get(str(pk), {"qty": 0, "price": float(product.price), "name": product.name})
    item["qty"] += 1
    cart[str(pk)] = item
    response = redirect("cart_view")
    return save_cart(response, cart)  # VULNERABILITY #11 - see shop/cart.py


def remove_from_cart(request, pk):
    cart = get_cart(request)
    cart.pop(str(pk), None)
    response = redirect("cart_view")
    return save_cart(response, cart)  # VULNERABILITY #11 - see shop/cart.py


@login_required
@csrf_exempt
def checkout(request):
    # VULNERABILITY #9 - CSRF (OWASP A01:2021). This state-changing endpoint
    # is explicitly exempted from Django's CSRF protection, so a malicious
    # page can auto-submit a form here on behalf of a logged-in victim.
    if request.method == "POST":
        cart = get_cart(request)
        computed_total = sum(item["price"] * item["qty"] for item in cart.values())
        # VULNERABILITY #10 - Business logic flaw: the order total is taken
        # directly from client-supplied POST data instead of always being
        # recomputed server-side, so a tampered `total` field is honored.
        total = request.POST.get("total") or computed_total
        order = Order.objects.create(
            user=request.user,
            total=total,
            shipping_address=request.POST.get("address", ""),
        )
        for pid, item in cart.items():
            OrderItem.objects.create(order=order, product_id=pid, quantity=item["qty"], price=item["price"])
        response = redirect("order_detail", order_id=order.id)
        return save_cart(response, {})
    return redirect("cart_view")


@login_required
def order_detail(request, order_id):
    # VULNERABILITY #8 - IDOR (OWASP A01:2021). No check that
    # order.user == request.user, so any logged-in user can read anyone
    # else's order (address, total, items) just by guessing/incrementing
    # order_id.
    order = get_object_or_404(Order, pk=order_id)
    return render(request, "shop/order_detail.html", {"order": order})


@login_required
def order_list(request):
    orders = Order.objects.all().order_by("-created_at")
    return render(request, "shop/order_list.html", {"orders": orders})


# ---------------------------------------------------------------------------
# "Extra features" - each one is a distinct, classic vulnerability class
# ---------------------------------------------------------------------------

@login_required
def apply_coupon(request):
    result = None
    error = None
    if request.method == "POST":
        try:
            price = float(request.POST.get("price", "0") or 0)
        except ValueError:
            price = 0.0
        formula = request.POST.get("formula", "price * 0.9")
        try:
            # VULNERABILITY #17 - Remote Code Execution via eval() (OWASP
            # A03:2021 - Injection). Passing a custom globals dict does NOT
            # make this safe: Python auto-populates '__builtins__' into any
            # globals dict that lacks it, so `__import__('os').system(...)`
            # style payloads still work. Try formula:
            #   __import__('os').popen('whoami').read()
            result = eval(formula, {"price": price})  # noqa: S307 - intentional vuln
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    return render(request, "shop/coupon.html", {"result": result, "error": error})


@login_required
def track_shipment(request):
    output = None
    if request.method == "POST":
        host = request.POST.get("host", "")
        # VULNERABILITY #15 - OS Command Injection (OWASP A03:2021). User
        # input is concatenated straight into a shell command. Try host:
        #   127.0.0.1 & whoami
        cmd = f"ping -n 1 {host}"
        output = subprocess.getoutput(cmd)
    return render(request, "shop/track_shipment.html", {"output": output})


@login_required
def email_preview(request):
    rendered = None
    error = None
    if request.method == "POST":
        template_content = request.POST.get("template_content", "")
        try:
            # VULNERABILITY #16 - Server-Side Template Injection (OWASP
            # A03:2021). A user-supplied string is compiled and rendered as
            # a live Django template instead of being treated as inert text.
            # Try: {% for c in user.get_all_permissions %}{{ c }}{% endfor %}
            t = Template(template_content)
            rendered = t.render(Context({"user": request.user}))
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    return render(request, "shop/email_preview.html", {"rendered": rendered, "error": error})


@login_required
def import_products_xml(request):
    created = 0
    error = None
    if request.method == "POST" and request.FILES.get("xml_file"):
        try:
            # VULNERABILITY #18 - XXE / XML External Entity injection (OWASP
            # A05:2021). resolve_entities=True + load_dtd=True lets an
            # uploaded DTD define external entities, which can be used to
            # read local files or perform SSRF. Try a DOCTYPE that defines
            # <!ENTITY xxe SYSTEM "file:///etc/passwd"> and references
            # &xxe; in a <name> element.
            parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
            tree = etree.parse(request.FILES["xml_file"], parser)
            for prod in tree.getroot().findall("product"):
                Product.objects.create(
                    name=prod.findtext("name") or "",
                    price=prod.findtext("price") or 0,
                )
                created += 1
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    return render(request, "shop/import_xml.html", {"created": created, "error": error})


@login_required
def import_image_url(request):
    status = None
    preview = None
    error = None
    if request.method == "POST":
        product_id = request.POST.get("product_id")
        url = request.POST.get("image_url", "")
        try:
            # VULNERABILITY #19 - SSRF (OWASP A10:2021). The server fetches
            # an attacker-supplied URL with no allow-list, letting it be
            # pointed at internal services or a cloud metadata endpoint,
            # e.g. http://169.254.169.254/latest/meta-data/
            resp = requests.get(url, timeout=5)
            status = resp.status_code
            preview = resp.text[:500]
            product = get_object_or_404(Product, pk=product_id)
            product.image_url = url
            product.save()
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    return render(request, "shop/import_image_url.html", {"status": status, "preview": preview, "error": error})
