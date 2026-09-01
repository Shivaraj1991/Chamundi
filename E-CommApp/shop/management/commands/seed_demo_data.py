import hashlib

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from shop.models import Category, Coupon, Product, UserProfile


class Command(BaseCommand):
    help = "Seed demo data for VulnShop (products, coupon, and a default admin account)."

    def handle(self, *args, **options):
        # VULNERABILITY #27 - Hardcoded default credentials (OWASP A07:2021).
        # A well-known admin/admin123 account shipped "for convenience" and
        # never forced to change on first login.
        if not User.objects.filter(username="admin").exists():
            admin = User(username="admin", email="admin@vulnshop.local", is_staff=True, is_superuser=True)
            admin.password = hashlib.md5(b"admin123").hexdigest()
            admin.save()
            UserProfile.objects.create(user=admin, api_key="00000001", role="admin")
            self.stdout.write(self.style.WARNING("Created default admin account: admin / admin123"))

        electronics, _ = Category.objects.get_or_create(name="Electronics")
        home, _ = Category.objects.get_or_create(name="Home & Kitchen")

        demo_products = [
            ("Wireless Mouse", "Ergonomic 2.4GHz wireless mouse.", 19.99, 50, electronics),
            ("Mechanical Keyboard", "RGB backlit mechanical keyboard.", 59.99, 30, electronics),
            ("4K Monitor", "27-inch 4K UHD monitor.", 249.99, 15, electronics),
            ("Coffee Maker", "12-cup programmable coffee maker.", 39.99, 20, home),
            ("Non-stick Pan Set", "3-piece non-stick frying pan set.", 34.99, 25, home),
        ]
        for name, desc, price, stock, category in demo_products:
            Product.objects.get_or_create(
                name=name,
                defaults={"description": desc, "price": price, "stock": stock, "category": category},
            )

        Coupon.objects.get_or_create(code="SAVE10", defaults={"formula": "price * 0.9"})

        self.stdout.write(self.style.SUCCESS("Demo data seeded."))
