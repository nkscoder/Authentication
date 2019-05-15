import uuid
import hashlib
import json
import bleach
from django.http import HttpResponse


def send_json(data, status=200, message=None):
    obj = {
        'status': int(status) if status is not None else 200,
        'message': message or 'Success',
        'data': data,
    }
    code = obj.get('status')
    if code != 200:
        raise APIException(detail=obj.get('message'), code=code)

    return Response(data=obj, status=code)
