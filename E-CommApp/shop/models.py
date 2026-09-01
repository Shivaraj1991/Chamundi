from django.contrib.auth.models import User
from django.db import models


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    bio = models.TextField(blank=True, default="")
    phone = models.CharField(max_length=20, blank=True, default="")
    avatar = models.CharField(max_length=255, blank=True, default="")

    # VULNERABILITY #28 - Sensitive data stored in plaintext (OWASP A02:2021 -
    # Cryptographic Failures). A real store must never store full card
    # numbers itself (PCI-DSS requires a tokenizing payment processor); here
    # it's kept in the clear and returned by the API (see api/views.py).
    credit_card_number = models.CharField(max_length=32, blank=True, default="")

    is_premium = models.BooleanField(default=False)

    # Distinct from Django's built-in is_staff/is_superuser so the API's
    # mass-assignment bug (VULNERABILITY #31) has an obviously "sensitive"
    # field to escalate, in addition to is_staff/is_superuser themselves.
    role = models.CharField(max_length=20, default="customer")

    reset_token = models.CharField(max_length=10, blank=True, default="")
    reset_token_created = models.DateTimeField(null=True, blank=True)

    # VULNERABILITY #6 - predictable, sequential, plaintext API key (see
    # shop/views.py register()).
    api_key = models.CharField(max_length=20, blank=True, default="")

    def __str__(self):
        return f"Profile<{self.user.username}>"


class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Product(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.IntegerField(default=0)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    image_url = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.name


class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="reviews")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    # VULNERABILITY #4 - Stored XSS: rendered with the `|safe` filter in
    # shop/templates/shop/product_detail.html instead of being auto-escaped.
    comment = models.TextField()
    rating = models.IntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)


class Coupon(models.Model):
    code = models.CharField(max_length=50, unique=True)
    formula = models.CharField(
        max_length=200,
        default="price * 0.9",
        help_text="Python expression evaluated against `price` via eval() - demo only.",
    )


class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_address = models.TextField(blank=True, default="")
    status = models.CharField(max_length=20, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    price = models.DecimalField(max_digits=10, decimal_places=2)
