import jwt
import string
import json
import re
from django.shortcuts import render
from rest_framework import viewsets
from rest_framework import status
from rest_framework.response import Response
from userauth.authentication import BearerTokenAuthentication
from django.contrib import auth
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token as RestToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from userauth.models import *
from userauth.utils import *
from django.core import serializers
from userauth.serializers import *
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from string import Template
import datetime as datetime_new
from datetime import datetime


from django.contrib.auth.models import User,Group
# Create your views here.


class AuthView(viewsets.ViewSet):
    def check_email(self, request):
        """
        Get function for checking email
        """
        email = request.data.get('email')
        if User.objects.filter(email=email).exists():
            return Response(data={'success': False, 'msg': 'Email already exists'},status=status.HTTP_200_OK)
        return Response(data={'success': True, 'msg': 'Email does not exist'},status=status.HTTP_200_OK)

    def check_username(self, request):
        """
        Get function for checking username
        """
        username = request.data.get('username')
        if User.objects.filter(username=username).exists():
            return Response(data={'success': False, 'msg': 'username already exists'},status=status.HTTP_200_OK)
        return Response(data={'success': True, 'msg': 'username is not exists'},status=status.HTTP_200_OK)


    def signup(self, request):
        """
        Get function for signup
        """

        if len(request.POST):
            request_data=request.POST
        else:
            request_data = request.data

        mobile = request_data.get('phone')
        email = request_data.get('email')
        password = request_data.get('password')
        confirm_password = request_data.get('con_password')
        fname = request_data.get('fname')
        lname = request_data.get('lname')

        result=email_validation(email)

        if mobile is '' or password is '' or confirm_password is '' or fname is '' or email is '':
              return Response(data={'success': False,'msg': 'All fields are required'}, status=status.HTTP_401_UNAUTHORIZED)
        #mobile validation
        pattern = re.compile('^\d{10}$')
        result_m = pattern.match(mobile)
        if result is None:
              return Response(data={'success': False,'msg': 'Invalid Email'}, status=status.HTTP_401_UNAUTHORIZED)

        if result_m is None:
              return Response(data={'success': False,'msg': 'Invalid mobile number'}, status=status.HTTP_401_UNAUTHORIZED)
        #retype password validation
        if password != confirm_password:
            return Response(data={'success': False,'msg': 'password and confirm password do not match.'}, status=status.HTTP_401_UNAUTHORIZED)
        if len(confirm_password) < 6:
            return Response(data={'success': False,'msg': 'Minimum password length is 6 characters.'}, status=status.HTTP_401_UNAUTHORIZED)
        #process the form if form is valid
        if User.objects.filter(email__iexact=email).exists():
            return Response(data={'success': False,'msg': 'Email already registered.'}, status=status.HTTP_401_UNAUTHORIZED)
        if User.objects.filter(username__iexact=mobile).exists():
            return Response(data={'success': False,'msg': 'Mobile already registered.'}, status=status.HTTP_401_UNAUTHORIZED)
        try:
                register_user(email=email,password=password,mobile=mobile,fname=fname,lname=lname)
                user=User.objects.get(email=email)
                token, created = RestToken.objects.get_or_create(user=user)
                auth.login(request, user)
                
                try:

                    template_l = Template('<p>Thank you for registering with $site_name. You can access your account by loggin in to - $site_login  with the email ID - $email and Your Password.</p><p>For any quries please contact : +$contact or email Us at $site_email</p><p>Regards,<br/>Team $site_name2 </p>').substitute(dict(site_name=settings.SITE_NAME, site_login=settings.SITE_LOGIN, email=email, contact=settings.SITE_CONTACT, site_email=settings.SITE_EMAIL, site_name2=settings.SITE_NAME))
                    dict_to_send = {"email": email, "subject": settings.SITE_NAME+"! Thanks for register with us", "html_message": template_l}
                    sendEmail(**dict_to_send)

  
                    #send the mail to the admin
                    template_l = Template('<p>New Registration on $site_name</p><br/><p>Fname: $fname<br/>Lname: $lname<br/>Email: $email<br/>Mobile: $mobile<br/>Date: $date</p>').substitute(dict({"site_name": settings.SITE_NAME, "fname": fname, "lname": lname, "email": email, "mobile": mobile, "date": datetime_new.datetime.strftime(datetime_new.datetime.today(), "%d/%m/%y")}))
                    for admin_email in admin_mails:
                        dict_to_send = {"email": admin_email, "subject": settings.SITE_NAME +"! New Registration on "+settings.SITE_NAME, "html_message": template_l}
                        sendEmail(**dict_to_send)


                        #send the thanks for the registration
                        # dict_to_send = {"email":email,"name":fname,"subject":settings.SITE_NAME +"! Thanks for register with us","template_name":'auth/email/user_register_template.html'}
                        # send_email(**dict_to_send)
                        # #send the emails to the admins
                        # for admin_email in admin_mails:
                        #     dict_to_send = {"email": admin_email, "user_email": email, "mobile": mobile, "name": fname+' '+lname, "subject": settings.SITE_NAME +
                        #                     "! New Registration On "+settings.SITE_NAME, "template_name": "auth/email/admin_user_register_template.html"}
                        #     send_email(**dict_to_send)
                    return Response(data={'success': True, 'user': UserSerializer(instance=list(getUser(request)), many=True).data, 'msg': 'Registration successful. kindly login now', 'token': str(token.key)}, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response(data={'success': True, 'user': UserSerializer(instance=list(getUser   (request)), many=True).data, 'msg': 'Registration successful. kindly login now', 'token': str(token.key)}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            pass
        return Response(data={'success': False,'msg': 'Some error occurred. Registration unsuccessfull'},status=status.HTTP_200_OK)


    def login(self,request):
        if request.method == "POST":
            username = request.data.get('username')
            password = request.data.get('password')
            if username is None or password is None:
                       return Response({'error': 'Please provide both username and password'},
                        status=HTTP_401_UNAUTHORIZED)

            if re.findall(r"\w+@\w+\.(?:com|in|org)",username):
                try:
                   data=User.objects.get(email=username)
                   username=data.username
                except Exception as e:

                    return Response(data={'success': False,'msg': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                # import ipdb; ipdb.set_trace()
                user=authenticate(username=username, password=password)
                if not user:
                    return Response(data={'success': False,'msg': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    auth.login(request, user)
                    token, created = RestToken.objects.get_or_create(user=user)
                     
                    profile = UserSerializer(instance=list(getUser(request)), many=True).data
                    
                    return Response(data={'success': True,'msg': 'User Authenticated successfully','profile':profile,'token': str(token.key)},status=status.HTTP_200_OK)
            except Exception as e:
                   return Response(data={'success': False,'msg': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
           return Response(data={'success': False,'msg': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

    def get_profile(self, request):
        try:
            data =UserSerializer(instance=list(getUser(request)), many=True).data 
            if data:
                return Response(data={'status': True,'data': data}, status=status.HTTP_200_OK)
            return Response(data={'status': False,'msg': 'User not found'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'status': False,'msg': 'User not found'}, status=status.HTTP_200_OK)
    
    def post_profile(self, request):
        try:
            result =  postProfile(request)
            data = UserSerializer(instance=list(getUser(request)), many=True).data
            if result:
                return Response(data={'status': True,"msg":"Profile has been successfully updated",'data': data}, status=status.HTTP_200_OK)
            return Response(data={'status': False,'msg': 'Profile has been not successfully updated'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'status': False,'msg': 'Profile has been not successfully updated'}, status=status.HTTP_200_OK)
    
                
        
    def generate_code(self, request):
        """
          Get function for generate_code
        """
        """Function to generate the otp send it to the user as well as set it for the user"""
        email = request.data.get('email') or None
        user = None

        try:
            user = User.objects.get(email=email)
        except Exception as e:
            return Response(data={'success': False, 'msg': 'Email does not exist'},status=status.HTTP_200_OK)

        token = jwt.encode({'exp': datetime.utcnow() + timedelta(hours=1)}, 'password',algorithm='HS256')
        token = token.decode('utf-8')
        code=generate_random_code()
        Token.objects.filter(user=user).delete()
        try:
            tok = Token()
            tok.user=user
            tok.token=token
            tok.code=code
            tok.save()
            url = settings.SERVER_ADDRESS + 'auth/reset/password/?token=' + token
            dict_to_send = {"email": email,'url':'none', 'code':code, "subject": settings.SITE_NAME+"!Forgot Password",
                            "template_name": 'auth/email/user_forgot_passwprd_template.html'}
            send_email(**dict_to_send)
            return Response(data={'success': True, 'token':token, 'msg': 'Kindly check your email to reset password'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'status': False, 'msg': 'No such email found in our records. Kindly register with us'},status=status.HTTP_200_OK)
        return Response(data={'status': False, 'msg': 'No such email found in our records. Kindly register with us'},status=status.HTTP_200_OK)



    def verify_code(self, request):
        """
        Get function for verify_code
        """

        try:
            code = request.data.get("code")
            user = request.data.get("user") 
            try:
                Token.objects.get(code=code)
                pass
            except:
                return Response(data={'success': False, 'msg': 'Otp does not exist.'},status=status.HTTP_200_OK)

                              
            if re.findall(r"\w+@\w+\.(?:com|in|org)",user):
                try:
                  data=Token.objects.filter(Q(code=code),Q(user_id=User.objects.get(email=user))).first()
                except Exception as e:
                    return Response(data={'success': False, 'msg': 'Token has been expired'},status=status.HTTP_200_OK)
            else:
                try:
                     data=Token.objects.filter(Q(code=code),Q(user_id=User.objects.get(username=user))).first() 
                except Exception as e:
                    return Response(data={'success': False, 'msg': 'Token has been expired'},status=status.HTTP_200_OK)           
            try:
                token=data.token
                jwt.decode(token, 'password', algorithms=['HS256'])
                return Response(data={'success': True, 'msg': 'Token has been not expired'},status=status.HTTP_200_OK)
            except Exception as e:
                pass
            return Response(data={'success': False, 'msg': 'Token has been expired'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'success': False, 'msg': 'Token has been expired'},status=status.HTTP_200_OK)

    def reset_password(self, request):
        """
		Get function for reset_password
		"""
        try:
            token = request.data.get("token") or None
            code = request.data.get("code") or None
            password = request.data.get("password")
            confirm_password = request.data.get("re_password")
            if password is None or confirm_password is None:
                return Response(data={'success': False, 'msg': 'Password or Re-Password are required'},
                                status=status.HTTP_401_UNAUTHORIZED)
            if password != confirm_password:
                return Response(data={'success': False, 'msg': 'Password and Re-Password do not match.'},
                                status=status.HTTP_401_UNAUTHORIZED)
            if len(confirm_password) < 6:
                return Response(data={'success': False, 'msg': 'Minimum password length is 6 characters.'},
                                status=status.HTTP_401_UNAUTHORIZED)
            if len(token) < 7:
                code=token
                token=None
            
            if not token == None:
                if not Token.objects.filter(token__iexact=token).exists():
                    return Response(data={'success': False, 'msg': 'token does not exist.'}, status=status.HTTP_200_OK)
                try:
                    jwt.decode(token, 'password', algorithms=['HS256'])
                    user_token = Token.objects.get(token=token)
                    user = User.objects.get(username=user_token.user.username)
                    user.set_password(password)
                    user.save()
                    user_token.delete()
                    return Response(data={'success': True, 'msg': 'Your password has been changed.'},
                                    status=status.HTTP_200_OK)
                except Exception as e:
                    return Response(data={'success': False, 'msg': 'Token has been expired.'}, status=status.HTTP_200_OK)
            
            if not code == None:
                if not Token.objects.filter(code__iexact=code).exists():
                    return Response(data={'success': False, 'msg': 'token does not exist.'}, status=status.HTTP_200_OK)
                try:

                   tok = Token.objects.filter(code=code).first()
                   token = tok.token
                   jwt.decode(token, 'password', algorithms=['HS256'])
                   user = User.objects.get(username=tok.user.username)
                   user.set_password(password)
                   user.save()
                   tok.delete()
                   return Response(data={'success': True, 'msg': 'Your password has been changed.'},
                                status=status.HTTP_200_OK)
                except Exception as e:
                   return Response(data={'success': False, 'msg': 'Token has been expired.'}, status=status.HTTP_200_OK)
        except Exception as e:
            pass
        return Response(data={'success': False, 'msg': 'Token has been expired.'}, status=status.HTTP_200_OK)
    
    def change_password(self, request):
        try:

            current_data = request.data
            old_password = current_data.get('old_password')
            new_password = current_data.get('new_password')
            confirm_password = current_data.get('confirm_password')
            user = request.user
            if new_password != confirm_password:
                return Response(data={'status': False, 'msg': 'Password and confirm password does not match.'}, status=status.HTTP_401_UNAUTHORIZED)
            if len(new_password) < 6:
                return Response(data={'status': False, 'msg': 'The password must contain at least 6 characters'},
                                status=status.HTTP_401_UNAUTHORIZED)
            if old_password == new_password:
                return Response(data={'status': False, 'msg': 'New password and old password can not be same'},
                                status=status.HTTP_401_UNAUTHORIZED)
            if user.check_password(old_password):
                u = User.objects.get(id=request.user.id)
                u.set_password(new_password)
                u.save()
                return Response(data={'status': True, 'msg': 'Your password has been changed successfully'}, status=status.HTTP_200_OK)
            else:
                return Response(data={'status': False, 'msg': 'Old password  does not match'},
                                status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response(data={'success': False, 'msg': 'Token has been expired.'}, status=status.HTTP_200_OK)
    
    def profile_update_image(self,request):
        try:
            request_data = request.data
            profile=Profile.objects.filter(user=request.user).first()
            profile.image=request_data.get('image')
            profile.save()
            data =ProfileSerializer(instance=list(getProfile(request)), many=True).data 
            return Response(data={'success': True,'data':data, 'msg': 'Your image has been successfully updated.'}, status=status.HTTP_200_OK)
           
        except Exception as e:
            return Response(data={'success': False, 'msg': 'Your image has been not updated.'}, status=status.HTTP_200_OK)
    
