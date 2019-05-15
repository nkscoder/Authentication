import jwt
import string
import json
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


        mobile = request.data.get('phone')
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('con_password')
        name = request.data.get('name')
     
        registration = request.data.get('registration')
        # import ipdb; ipdb.set_trace()
        result=email_validation(email)

        if mobile is '' or password is '' or confirm_password is '' or name is '' or email is '':
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
                register_user(email=email,password=password,mobile=mobile,name=name,registration=registration)
                user=User.objects.get(email=email)
                token, created = RestToken.objects.get_or_create(user=user)
                auth.login(request, user)
                
                try:
                        #send the thanks for the registration
                        dict_to_send = {"email":email,"name":name,"subject":"On Leave! Thanks for register with us","template_name":'email/user_register_template.html'}
                        send_email(**dict_to_send)
                        #send the emails to the admins
                        for admin_email in admin_mails:
                            dict_to_send = {"email":admin_email,"user_email":email,"mobile":mobile,"name":name,"subject":"On Leave! New Registration On  ONLeave.IN","template_name":"email/admin_user_register_template.html"}
                            send_email(**dict_to_send)
                        return Response(data={'success': True,'profile':ProfileSerializer(instance=list(getProfile(request)), many=True).data ,'msg': 'Registration successful. kindly login now','token': str(token.key)},status=status.HTTP_200_OK)
                except Exception as e:
                   return Response(data={'success': True,'profile':ProfileSerializer(instance=list(getProfile(request)), many=True).data ,'msg': 'Registration successful. kindly login now','token': str(token.key)},status=status.HTTP_200_OK)
        except Exception as e:
            # import ipdb; ipdb.set_trace()
            pass
        return Response(data={'success': True,'msg': 'Some error occurred. Registration unsuccessfull','token': str(token.key)},status=status.HTTP_200_OK)


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
                     
                    profile=ProfileSerializer(instance=list(getProfile(request)), many=True).data 
                    
                    return Response(data={'success': True,'msg': 'User Authenticated successfully','profile':profile,'token': str(token.key)},status=status.HTTP_200_OK)
            except Exception as e:
                   return Response(data={'success': False,'msg': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
           return Response(data={'success': False,'msg': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

    def get_profile(self, request):
        try:
            data =ProfileSerializer(instance=list(getProfile(request)), many=True).data 
            if data:
                return Response(data={'status': True,'data': data}, status=status.HTTP_200_OK)
            return Response(data={'status': False,'msg': 'User not found'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'status': False,'msg': 'User not found'}, status=status.HTTP_200_OK)
    
    def post_profile(self, request):
        try:
            result =  postProfile(request)
            data =ProfileSerializer(instance=list(getProfile(request)), many=True).data
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
        mobile = request.data.get('mobile') or None
        email = request.data.get('email') or None
        user = None
        if not mobile == None:
            try:
                user = User.objects.get(username=mobile)
            except Exception as e:
                    return Response(data={'success': False, 'msg': 'Mobile is not exists'},status=status.HTTP_200_OK)

        if not email == None:
            try:
               # import ipdb; ipdb.set_trace()
               user = User.objects.get(email=email)
            except Exception as e:
                # import ipdb; ipdb.set_trace()
                return Response(data={'success': False, 'msg': 'Email does not exist'},status=status.HTTP_200_OK)

        if user == None:
            return Response(data={'success': False, 'msg': 'Email or Mobile is not exists'},status=status.HTTP_200_OK)

        token = jwt.encode({'exp': datetime.utcnow() + timedelta(hours=1)}, 'password',algorithm='HS256')
        token = token.decode('utf-8')
        code=generate_random_code()
        Token.objects.filter(user=user).delete()
        if not mobile == None:
            try:
                import http.client
                conn = http.client.HTTPConnection("api.msg91.com")
                msg = 'Hi User, To reset the password for My On Leave account, please enter the following code: {}'.format(code)
                conn.request("GET", "/api/sendhttp.php?sender=PORTAL&route=4&mobiles=" + mobile + "&authkey=&country=91&message=" + msg)
                res = conn.getresponse()
                data = res.read()
                tok=Token()
                tok.user=user
                tok.token=token
                tok.code=code
                tok.save()
                return Response(data={'success': True, 'token':token,'msg': 'Send Otp on mobile number'},status=status.HTTP_200_OK)
            except Exception as e:

                return Response(data={'success': False, 'msg': 'Do not Send Otp on mobile number'},status=status.HTTP_200_OK)

        if not email == None:
            try:
                tok = Token()
                tok.user=user
                tok.token=token
                tok.code=code
                tok.save()
                url = settings.SERVER_ADDRESS + 'reset/password/?token=' + token
                dict_to_send = {"email": email,'url':'none', 'code':code, "subject": "On Leave!Forgot Password",
                                "template_name": 'email/user_forgot_passwprd_template.html'}
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
    
