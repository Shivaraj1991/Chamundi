from django.contrib import admin

from .models import Category, Coupon, Order, OrderItem, Product, Review, UserProfile

admin.site.register(UserProfile)
admin.site.register(Category)
admin.site.register(Product)
admin.site.register(Review)
admin.site.register(Coupon)
admin.site.register(Order)
admin.site.register(OrderItem)
