from .cart import get_cart


def cart_context(request):
    cart = get_cart(request)
    count = sum(item.get("qty", 0) for item in cart.values())
    return {"cart_count": count}
