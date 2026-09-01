class InsecureCorsMiddleware:
    """
    VULNERABILITY #26 - CORS Misconfiguration (OWASP A05:2021 - Security Misconfiguration)

    Reflects whatever Origin header the caller sends back in
    Access-Control-Allow-Origin, and pairs it with
    Access-Control-Allow-Credentials: true. That combination lets ANY
    external website read authenticated API/JSON responses from a
    logged-in victim's browser via fetch(url, {credentials: 'include'}),
    completely defeating the same-origin policy.

    Fix: use an explicit allow-list of trusted origins and never combine
    a reflected/"*" origin with allow-credentials.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        origin = request.META.get("HTTP_ORIGIN", "*")
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Allow-Headers"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        return response
