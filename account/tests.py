from django.test import TestCase
from django.urls import reverse

from .models import UserRegistration


class RegistrationTests(TestCase):
    def test_registration_starts_a_session_and_hashes_password(self):
        response = self.client.post(reverse('register'), {
            'full_name': 'New User',
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123',
            'agreed_to_terms': 'on',
        })

        user = UserRegistration.objects.get(username='newuser')
        self.assertRedirects(response, reverse('create_post'))
        self.assertEqual(self.client.session['user_id'], user.id)
        self.assertNotEqual(user.password, 'password123')
        self.assertEqual(user.confirm_password, '')

    def test_duplicate_registration_shows_errors_without_crashing(self):
        UserRegistration.objects.create(
            full_name='Existing User', username='taken', email='taken@example.com',
            password='legacy-password', confirm_password='legacy-password',
        )
        response = self.client.post(reverse('register'), {
            'full_name': 'Another User', 'username': 'taken',
            'email': 'taken@example.com', 'password': 'password123',
            'confirm_password': 'password123', 'agreed_to_terms': 'on',
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(UserRegistration.objects.count(), 1)


class LoginTests(TestCase):
    def test_new_account_can_login_with_username_or_case_insensitive_email(self):
        self.client.post(reverse('register'), {
            'full_name': 'New User', 'username': 'newuser',
            'email': 'newuser@example.com', 'password': 'password123',
            'confirm_password': 'password123', 'agreed_to_terms': 'on',
        })

        response = self.client.post(reverse('login'), {
            'login_input': 'NEWUSER@EXAMPLE.COM', 'password': 'password123',
        })

        self.assertRedirects(response, reverse('home'))
        self.assertEqual(self.client.session['full_name'], 'New User')

    def test_legacy_plaintext_password_is_upgraded_after_successful_login(self):
        user = UserRegistration.objects.create(
            full_name='Legacy User', username='legacy', email='legacy@example.com',
            password='old-password', confirm_password='old-password',
        )

        response = self.client.post(reverse('login'), {
            'login_input': 'legacy', 'password': 'old-password',
        })

        user.refresh_from_db()
        self.assertRedirects(response, reverse('home'))
        self.assertNotEqual(user.password, 'old-password')

    def test_invalid_password_shows_login_error(self):
        UserRegistration.objects.create(
            full_name='User', username='user', email='user@example.com',
            password='right-password', confirm_password='right-password',
        )

        response = self.client.post(reverse('login'), {
            'login_input': 'user', 'password': 'wrong-password',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid username/email or password.')
