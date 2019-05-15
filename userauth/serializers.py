from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.fields import CurrentUserDefault


class UserSerializer(serializers.ModelSerializer):
    """docstring for User Serializer."""
    class Meta:
        model = User
        fields = ('__all__')
