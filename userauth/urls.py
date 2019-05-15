from django.conf.urls import url, include, re_path
from .views import *
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [

    re_path(r'^auth/check/email/?$',
            AuthView.as_view({'post': 'check_email'})),
    re_path(r'^auth/check/username/?$',
            AuthView.as_view({'post': 'check_username'})),
    re_path(r'^auth/signup/?$', AuthView.as_view({'post': 'signup'})),
    re_path(r'^auth/login/?$', AuthView.as_view({'post': 'login'})),
    re_path(r'^auth/generate/code/?$',
            AuthView.as_view({'post': 'generate_code'})),
    re_path(r'^auth/verify/code/?$',
            AuthView.as_view({'post': 'verify_code'})),
    re_path(r'^auth/reset/password/?$',
            AuthView.as_view({'post': 'reset_password'})),
    re_path(r'^auth/get/profile/?$', AuthView.as_view({'get': 'get_profile'})),
    re_path(r'^auth/post/profile/?$',
            AuthView.as_view({'post': 'post_profile'})),
    re_path(r'^auth/change/password/?$',
            AuthView.as_view({'post': 'change_password'})),
    # re_path(r'^auth/profile/update/image/?$',
    #         AuthView.as_view({'post': 'profile_update_image'})),

    # re_path(r'^image/upload/?$', UploadView.as_view({'post': 'image_upload'})),


    #



]
