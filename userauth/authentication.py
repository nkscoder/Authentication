from rest_framework.authentication import TokenAuthentication

# rename token to bearer in api header


class BearerTokenAuthentication(TokenAuthentication):
    keyword = 'Bearer'
