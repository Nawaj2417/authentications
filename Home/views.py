import random
from rest_framework import generics,status,views,permissions,serializers
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import RegisterSerializer,LoginSerializer,LogoutSerializer,PasswordResetSerializer,UsernameResetSerializer
from .models import User
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    def post(self,request):
        user=request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        is_superuser = serializer.validated_data.get('is_superuser', False)
        is_staff = serializer.validated_data.get('is_staff', False)
        serializer.save()
        user_data = serializer.data
        return Response(user_data, status=status.HTTP_201_CREATED)
class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(username=serializer.validated_data['username'])
        
        if user.is_authorized:
            response_data = serializer.validated_data
            response_data["detail"] = "Logged in successfully."
        # Generate a refresh token and set it for the user
            refresh = RefreshToken.for_user(user)
            user.refresh_token = str(refresh)
            user.save()

            response = Response(response_data, status=status.HTTP_200_OK)
            # response.set_cookie('login_status', 'success', secure=True, samesite='None')
            response.set_cookie('refreshToken', user.refresh_token, secure=True, samesite='None')
            
            return response
        else:
            return Response({"detail": "Your account has not been approved by an admin yet."}, status=status.HTTP_400_BAD_REQUEST)

class TokenLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        token = request.data.get('token')
        

        user = User.objects.filter(username=username, login_token=token).first()
        if user is not None:
            # The token is correct. You can log in the user here.
            user.login_token = None  # Clear the token
            user.save()
            
            response = Response({"detail": "Logged in successfully."}, status=status.HTTP_200_OK)
            # response.set_cookie('refreshToken', token.refreshToken, secure=True, samesite='None')
            response.set_cookie('refreshToken', user.tokens.refresh, secure=True, samesite='None')
            
            return response
        else:
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.permissions import AllowAny
class LogoutAPIView(generics.GenericAPIView):
    authentication_classes = []
    serializer_class = LogoutSerializer
    @permission_classes([AllowAny])
    # permission_classes = (permissions.IsAuthenticated,)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)


# For sending OTP via email for password reset
class PasswordResetOTPEmailView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        data = serializer.save()

        # Generate a unique confirmation URL for your local server
        confirmation_url_password_reset = f'http://localhost:8000/reset-password-confirmation/?email={email}&otp={data["otp"]}'


        # Send an email with the OTP and the confirmation link
        subject = 'Password Reset OTP and Confirmation Link'
        message = f'Use this OTP to reset your password: {data["otp"]}\n\n'
        message += f'\n\nAlternatively, you can click on the link below to reset your password:\n{confirmation_url_password_reset}'

        from_email = 'webmaster@example.com'
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)

        return Response({'message': 'Password reset OTP and confirmation link sent successfully.'}, status=status.HTTP_200_OK)

from django.contrib import messages
from django.shortcuts import render, redirect
from django.views.generic import DetailView
from django.views import View
from django.http import HttpResponseBadRequest
from django.http import Http404

# For verifying OTP for password reset and setting a new password
class PasswordResetConfirmationView(DetailView):
    model = User
    template_name = 'password_reset_confirmation.html'
    context_object_name = 'user'

    def get_object(self, queryset=None):
        email = self.request.GET.get('email')
        otp = self.request.GET.get('otp')

        if not email or not otp:
            raise Http404("Invalid URL")

        user = User.objects.filter(email=email, login_token=otp).first()

        if user is None:
            raise Http404("Invalid OTP")

        return user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        new_password = request.POST.get('password')

        # Set the new password
        user.set_password(new_password)
        user.save()

        messages.success(request, 'Password reset successfully.')
        return redirect('Home:login')  # Redirect to the login page
    

# For sending OTP via email for username reset
class UsernameResetOTPEmailView(generics.CreateAPIView):
    serializer_class = UsernameResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        data = serializer.save()
# Generate a unique confirmation URL for your local server
        confirmation_url_username_reset = f'http://localhost:8000/reset-username-confirmation/?email={email}&otp={data["otp"]}'

        # Send an email with the OTP for username reset
        subject = 'Username Reset OTP'
        message = f'Use this OTP to reset your username: {data["otp"]}'
        message += f'\n\nAlternatively, you can click on the link below to reset your username:\n{confirmation_url_username_reset}'
        from_email = 'webmaster@example.com'
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)

        return Response({'message': 'Username reset OTP sent successfully.'}, status=status.HTTP_200_OK)


# For verifying OTP for username reset and setting a new username
from rest_framework.exceptions import ValidationError

# For verifying OTP for username reset and setting a new username
class UsernameResetConfirmationView(View):
    # model = User
    template_name = 'username_reset_confirmation.html'
    # context_object_name = 'user'
    
    def get(self, request, *args, **kwargs):
        email = request.GET.get('email')
        otp = request.GET.get('otp')

        if not email or not otp:
            return HttpResponseBadRequest("Invalid URL")

        # Check if the OTP entered in the URL matches the one sent via email
        user = User.objects.filter(email=email, username_reset_token=otp).first()

        if user is None:
            return HttpResponseBadRequest("Invalid OTP")

        return render(request, self.template_name, {'email': email, 'otp': otp})

    def post(self, request, *args, **kwargs):
        email = request.GET.get('email')
        otp = request.GET.get('otp')

        # Verify the OTP again before allowing the user to reset the username
        user = User.objects.filter(email=email, username_reset_token=otp).first()

        if user is None:
            return HttpResponseBadRequest("Invalid OTP")

        # Set the new username
        new_username = request.POST.get('username')

        # Check if the new username is available
        if User.objects.filter(username=new_username).exists():
            messages.error(request, 'Username is already in use.')
            return redirect('reset-username-email')  # Redirect back to the username reset email page

        user.username = new_username
        user.save()

        messages.success(request, 'Username reset successfully.')
        return redirect('Home:login')  # Redirect to the login page
    