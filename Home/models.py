from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
class User(AbstractUser):
    username_reset_token = models.CharField(max_length=6,null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_authorized = models.BooleanField(default=False)
    login_token = models.CharField(max_length=6, blank=True, null=True)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    
    def __str__(self):
        return self.username

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return{
            'refresh':str(refresh),
            'access':str(refresh.access_token)
        }
