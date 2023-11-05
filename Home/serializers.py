from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.crypto import get_random_string

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    is_superuser = serializers.BooleanField(default=False)
    is_staff = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = ['email', 'username', 'password','is_superuser', 'is_staff']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages)
        return attrs
    

    def create(self, validated_data):
        # Use Django's built-in method for creating a user
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            is_superuser=validated_data['is_superuser'],
            is_staff=validated_data['is_staff']
        )
        # Use set_password method to hash the password
        user.set_password(validated_data['password'])
        user.save()
        return user    
class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3)
    tokens = serializers.SerializerMethodField()
    def get_tokens(self, obj):
        user = User.objects.get(username=obj['username'])
        return user.tokens
    class Meta:
        model = User
        fields = ['password', 'username','tokens']

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        
        # Check if the username exists
        if not User.objects.filter(username=username).exists():
            raise AuthenticationFailed('Invalid username, try again')
        
        user = auth.authenticate(username=username, password=password)
        
        # Check if the password is correct
        if user is None:
            raise AuthenticationFailed('Invalid password, try again')
            
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
            
        if not user.is_authorized:
            raise AuthenticationFailed('Your account has not been approved by an admin yet.')
            
        return {
            'email': user.email,
            'username': user.username,
             'tokens': user.tokens()
        }
    

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError as e:
            # self.fail('bad_token')
            raise serializers.ValidationError(str(e))

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = User.objects.filter(email=value).first()
        if user is None:
            raise serializers.ValidationError("No user found with this email address.")
        return value

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
                # Generate a 6-digit numeric OTP
        otp = get_random_string(length=6, allowed_chars='1234567890')
        user.login_token = otp
        user.save()
        return {'user': user, 'otp': otp}
    

class UsernameResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = User.objects.filter(email=value).first()
        if user is None:
            raise serializers.ValidationError("No user found with this email address.")
        return value

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        # Generate a 6-digit numeric OTP
        otp = get_random_string(length=6, allowed_chars='1234567890')
        user.username_reset_token = otp
        user.save()
        return {'user': user, 'otp': otp}
