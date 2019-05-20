from authentication.settings import *
from django.core.mail import send_mail, EmailMessage
from django.template.loader import get_template
from datetime import datetime, timedelta
from django.shortcuts import render
from django.core.mail import EmailMultiAlternatives
from django.template import Context
from .models import *
from .app_settings import admin_mails
# from api.app_settings import *
from django.http import HttpResponse, HttpResponseRedirect

from django.core.files import File
from django.core.files.storage import FileSystemStorage
from django.core.mail import EmailMessage
from datetime import datetime, date
from django.db.models import Q
from django.conf import settings
from email.mime.image import MIMEImage
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import authenticate
from django.contrib.auth.models import User, Group
# from api.serializers import *
from django.utils import timezone
import pytz
import json
import random
import hashlib
import re
import string
import base64


def sendEmail(*args, **kwargs):
    """function to handle the email sending"""
    sub = kwargs.get('subject')
    message = kwargs.get('message', None)
    from_email = settings.USEEMAIL
    template_email_text = message
    email = kwargs.get('email', None)
    html_message = kwargs.get('html_message', None)

    send_mail(sub, template_email_text, settings.DEFAULT_FROM_EMAIL, [
              email], fail_silently=False, html_message=html_message)

def send_email(*args, **kwargs):
    """function to handle the email sending"""
    try:
        pdf = None

        if kwargs.get('pdf'):
            pdf = kwargs.get('pdf')
        doc_files = None
        if kwargs.get('doc_files'):
            doc_files = kwargs.get('doc_files')

        subject = kwargs.get('subject')
        email = kwargs.get('email')
        template_name = kwargs.get('template_name')
        plaintext = get_template('auth/email/email.txt')
        htmly = get_template(template_name)
        user_context = kwargs
        text_content = plaintext.render(user_context)
        html_content = htmly.render(user_context)
        email = EmailMultiAlternatives(subject, text_content, to=[email])
        if not doc_files == None:
            email.attach(str(doc_files).split(
                'uploads/').pop(), doc_files.read())
        if not pdf == None:
            html = get_template(kwargs.get('pdf')).render(user_context)
            file_to_be_sent = generatePdf(html=html)
            email.attach("Invoice.pdf", file_to_be_sent, "application/pdf")
        email.attach_alternative(html_content, "text/html")
        email.send()

        return True

    except Exception as e:
        return False


def generatePdf(*args, **kwargs):
    import pdfkit
    str_data = kwargs.pop("html")
    return pdfkit.from_string(str_data, False)


def email_validation(email):
    pattern = re.compile(
        '^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$')
    if pattern.match(email):
        return True
    return None


def authenticate_user(username, password):
    """
    Util function for logging in user
    """
    current_user = authenticate(username=username, password=password)
    authed = False
    if current_user:
        authed = True
    return authed, current_user


def register_user(*args, **kwargs):
    """function to register the user"""
    try:
        email = kwargs.pop("email")
        password = kwargs.pop("password")
        mobile = kwargs.pop("mobile")
        fname = kwargs.pop("fname")
        lname = kwargs.pop("lname")
        user = User.objects.create_user(mobile, email, password)
        user.first_name = fname
        user.last_name = lname
        user.save()
        return True
    except Exception as e:

        return False


def generate_random_code(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def postProfile(request):
    try:
        if len(request.POST):
            request_data = request.POST
        else:
            request_data = request.data

        if not request_data.get('email') == '' and not request_data.get('email') == None:
            if request_data.get('email'):
                user = User.objects.filter(
                    username=request.user.username).first()
                user.email = request_data.get('email')
                user.save()

        return True
    except Exception as e:
        return False


def getUser(request):
    data = ''
    try:
        return User.objects.filter(username=request.user.username)
    except:
        return data


def uploadImageinBase64(request):
    from mimetypes import guess_extension, guess_type
    data = json.loads(request.body.decode())
    urls = []

    image_data = data['image']
    try:

        name = randomname_generator(random.randint(
            5, 10)) + datetime.now().strftime("%Y%m%d%H%M%S_%f")

        extension = guess_extension(guess_type(
            image_data[:image_data.find(",") + 1])[0])

        name = name + extension

        with open(settings.MEDIA_ROOT + "images/" + name, "wb") as fh:
            fh.write(base64.decodebytes(str.encode(
                image_data[image_data.find(",") + 1:])))
            urls.append("images/" + name)
            print(urls)

        return urls
    except Exception as e:
        return False


def randomname_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
