from django.test import TestCase

# Create your tests here.
# tests.py

from django.urls import reverse
from rest_framework.test import APIClient, APITestCase
from .models import User

class UserTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')

    def test_logout(self):
        # Log in
        response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'testpass'})
        token = response.data['tokens']['access']

        # Log out
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)
        response = self.client.post(self.logout_url)

        # Check response status code
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_logout(self):
        # Attempt to log out without logging in
        response = self.client.post(self.logout_url)

        # Check response status code
        self.assertEqual(response.status_code, 401)
