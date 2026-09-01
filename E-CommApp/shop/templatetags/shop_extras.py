from django import template

register = template.Library()


@register.filter
def stars(rating):
    """Render an integer 1-5 rating as filled/empty star glyphs for display."""
    try:
        rating = int(rating)
    except (TypeError, ValueError):
        rating = 0
    rating = max(0, min(5, rating))
    return "★" * rating + "☆" * (5 - rating)


@register.filter
def mul(value, arg):
    try:
        return float(value) * float(arg)
    except (TypeError, ValueError):
        return ""
