import datetime
import logging
import collections
from cStringIO import StringIO

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model, SESSION_KEY
from django.core.urlresolvers import reverse
from django.utils import timezone

from django_auth_policy.forms import (StrictAuthenticationForm,
                                      StrictPasswordChangeForm)
from django_auth_policy.models import LoginAttempt, PasswordChange
from django_auth_policy.backends import StrictModelBackend
from django_auth_policy import settings as dap_settings


class LoginTests(TestCase):
    urls = 'django_auth_policy.tests.urls'

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username='rf',
            email='rf@example.rf',
            password='password')

        self.factory = RequestFactory()

        self.logger = logging.getLogger()
        self.old_stream = self.logger.handlers[0].stream
        self.logger.handlers[0].stream = StringIO()

    def tearDown(self):
        self.logger.handlers[0].stream = self.old_stream

    def test_success(self):
        """ Test view with form and successful login """
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)

        resp = self.client.post(reverse('login'), data={
            'username': 'rf', 'password': 'password'})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(SESSION_KEY in self.client.session)
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)

        attempts = LoginAttempt.objects.filter(username=self.user.username,
                                               successful=True)

        self.assertEqual(attempts.count(), 1)

        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'INFO Authentication success, username=rf, address=127.0.0.1\n'
            u'INFO User rf must change password\n'))

    def test_username_lockout(self):
        """ Test too many failed login attempts for one username """

        for x in xrange(0, dap_settings.FAILED_AUTH_USERNAME_MAX):

            req = self.factory.get(reverse('login'))
            req.META['REMOTE_ADDR'] = '10.0.0.%d' % (x + 1)

            form = StrictAuthenticationForm(request=req, data={
                'username': 'rf', 'password': 'wrong password'})

            self.assertEqual(form.non_field_errors(), [
                form.error_messages['invalid_login'] % {
                    'username': form.username_field.verbose_name}])

        attempts = LoginAttempt.objects.filter(username=self.user.username,
                                               successful=False, lockout=True)

        self.assertEqual(attempts.count(),
                         dap_settings.FAILED_AUTH_USERNAME_MAX)

        # Another failed authentication triggers lockout
        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'wrong password'})
        self.assertEqual(form.non_field_errors(), [
            form.error_messages['username_locked_out']])

        self.assertEqual(attempts.count(),
                         dap_settings.FAILED_AUTH_USERNAME_MAX + 1)

        # Even valid authentication will no longer work now
        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'password'})
        self.assertFalse(form.is_valid())

        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf, address=10.0.0.1\n'
            u'WARNING Authentication failure, username=rf, address=10.0.0.1, '
            u'invalid authentication.\n'
            u'INFO Authentication attempt, username=rf, address=10.0.0.2\n'
            u'WARNING Authentication failure, username=rf, address=10.0.0.2, '
            u'invalid authentication.\n'
            u'INFO Authentication attempt, username=rf, address=10.0.0.3\n'
            u'WARNING Authentication failure, username=rf, address=10.0.0.3, '
            u'invalid authentication.\n'
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'WARNING Authentication failure, username=rf, address=127.0.0.1, '
            u'username locked\n'
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'WARNING Authentication failure, username=rf, address=127.0.0.1, '
            u'username locked\n'))

    def test_address_lockout(self):
        """ Test too many failed login attempts for one address """

        addr = '1.2.3.4'

        for x in xrange(0, dap_settings.FAILED_AUTH_ADDRESS_MAX):

            req = self.factory.get(reverse('login'))
            req.META['REMOTE_ADDR'] = addr

            form = StrictAuthenticationForm(request=req, data={
                'username': 'rf%d' % x, 'password': 'wrong password'})

            self.assertEqual(form.non_field_errors(), [
                form.error_messages['invalid_login'] % {
                    'username': form.username_field.verbose_name}])

        attempts = LoginAttempt.objects.filter(source_address=addr,
                                               successful=False, lockout=True)

        self.assertEqual(attempts.count(),
                         dap_settings.FAILED_AUTH_ADDRESS_MAX)

        # Another failed authentication triggers lockout
        req = self.factory.get(reverse('login'))
        req.META['REMOTE_ADDR'] = addr
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'wrong password'})
        self.assertEqual(form.non_field_errors(), [
            form.error_messages['address_locked_out']])

        self.assertEqual(attempts.count(),
                         dap_settings.FAILED_AUTH_ADDRESS_MAX + 1)

        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf0, address=1.2.3.4\n'
            u'WARNING Authentication failure, username=rf0, address=1.2.3.4, '
            u'invalid authentication.\n'
            u'INFO Authentication attempt, username=rf1, address=1.2.3.4\n'
            u'WARNING Authentication failure, username=rf1, address=1.2.3.4, '
            u'invalid authentication.\n'
            u'INFO Authentication attempt, username=rf2, address=1.2.3.4\n'
            u'WARNING Authentication failure, username=rf2, address=1.2.3.4, '
            u'invalid authentication.\n'
            u'INFO Authentication attempt, username=rf, address=1.2.3.4\n'
            u'WARNING Authentication failure, username=rf, address=1.2.3.4, '
            u'address locked\n'))

    def test_inactive_user(self):
        self.user.is_active = False
        self.user.save()

        # Valid authentication data, but user is inactive
        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'password'})
        self.assertFalse(form.is_valid())
        self.assertEqual(form.non_field_errors(), [
            form.error_messages['inactive']])

        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'WARNING Authentication failure, username=rf, address=127.0.0.1, '
            u'user inactive.\n'))

    def test_lock_period(self):
        for x in xrange(0, dap_settings.FAILED_AUTH_USERNAME_MAX + 1):

            req = self.factory.get(reverse('login'))

            form = StrictAuthenticationForm(request=req, data={
                'username': 'rf', 'password': 'wrong password'})

            self.assertFalse(form.is_valid())

        # User locked out
        self.assertEqual(form.non_field_errors(), [
            form.error_messages['username_locked_out']])

        # Alter timestamps as if they happened longer ago
        period = datetime.timedelta(
            seconds=dap_settings.FAILED_AUTH_LOCKOUT_PERIOD)
        expire_at = timezone.now() - period
        LoginAttempt.objects.all().update(timestamp=expire_at)

        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'password'})
        self.assertTrue(form.is_valid())

        # Successful login resets lock count
        locking_attempts = LoginAttempt.objects.filter(lockout=True)
        self.assertEqual(locking_attempts.count(), 0)

    def test_unlock(self):
        """ Resetting lockout data unlocks user """
        for x in xrange(0, dap_settings.FAILED_AUTH_USERNAME_MAX + 1):

            req = self.factory.get(reverse('login'))

            form = StrictAuthenticationForm(request=req, data={
                'username': 'rf', 'password': 'wrong password'})

            self.assertFalse(form.is_valid())

        # User locked out
        self.assertEqual(form.non_field_errors(), [
            form.error_messages['username_locked_out']])

        # Unlock user or address
        LoginAttempt.objects.all().update(lockout=False)

        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'password'})
        self.assertTrue(form.is_valid())

    def test_backend_locked_username(self):
        # Authentication works
        backend = StrictModelBackend()
        user = backend.authenticate(username='rf', password='password')
        self.assertEqual(user, self.user)

        # Lock user
        for x in xrange(0, dap_settings.FAILED_AUTH_USERNAME_MAX + 1):
            req = self.factory.get(reverse('login'))
            form = StrictAuthenticationForm(request=req, data={
                'username': 'rf', 'password': 'wrong password'})
            self.assertFalse(form.is_valid())

        # Authentication must no longer work for this user
        user = backend.authenticate(username='rf', password='password')
        self.assertEqual(user, None)


class UserExpiryTests(TestCase):
    urls = 'django_auth_policy.tests.urls'

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username='rf',
            email='rf@example.rf',
            password='password')

        self.factory = RequestFactory()

        self.logger = logging.getLogger()
        self.old_stream = self.logger.handlers[0].stream
        self.logger.handlers[0].stream = StringIO()

    def tearDown(self):
        self.logger.handlers[0].stream = self.old_stream

    def test_expiry(self):
        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'password'})
        self.assertTrue(form.is_valid())

        # Simulate user didn't log in for a long time
        period = datetime.timedelta(days=dap_settings.INACTIVE_USERS_EXPIRY)
        expire_at = timezone.now() - period
        self.user.last_login = expire_at
        self.user.save()
        LoginAttempt.objects.all().update(timestamp=expire_at)

        # Login attempt disabled user
        req = self.factory.get(reverse('login'))
        form = StrictAuthenticationForm(request=req, data={
            'username': 'rf', 'password': 'password'})
        self.assertFalse(form.is_valid())
        self.assertEqual(form.non_field_errors(), [
            form.error_messages['inactive']])

        # Check log messages
        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'INFO Authentication success, username=rf, address=127.0.0.1\n'
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'WARNING User rf disabled because last login was at %s\n'
            u'WARNING Authentication failure, username=rf, address=127.0.0.1, '
            u'user inactive.\n' % expire_at))

    def test_backend_expired_user(self):
        # Authentication works
        backend = StrictModelBackend()
        user = backend.authenticate(username='rf', password='password')
        self.assertEqual(user, self.user)
        self.assertTrue(user.is_active)

        # Simulate user didn't log in for a long time
        period = datetime.timedelta(days=dap_settings.INACTIVE_USERS_EXPIRY)
        expire_at = timezone.now() - period
        self.user.last_login = expire_at
        self.user.save()
        LoginAttempt.objects.all().update(timestamp=expire_at)

        # Authentication must still work for this user, but user is inactive
        user = backend.authenticate(username='rf', password='password')
        self.assertEqual(user, self.user)
        self.assertFalse(user.is_active)


class PasswordChangeTests(TestCase):
    urls = 'django_auth_policy.tests.urls'

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username='rf',
            email='rf@example.rf',
            password='password')

        self.factory = RequestFactory()

        self.logger = logging.getLogger()
        self.old_stream = self.logger.handlers[0].stream
        self.logger.handlers[0].stream = StringIO()

    def tearDown(self):
        self.logger.handlers[0].stream = self.old_stream

    def test_expiry(self):
        # Create one recent password change
        pw = PasswordChange.objects.create(user=self.user, successful=True,
                                           is_temporary=False)

        # Redirect to login
        resp = self.client.get(reverse('login_required_view'), follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.request['PATH_INFO'], reverse('login'))

        # Login
        resp = self.client.post(reverse('login'), data={
            'username': 'rf', 'password': 'password'}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(SESSION_KEY in self.client.session)
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
        self.assertTrue('password_change_enforce' in self.client.session)
        self.assertFalse(self.client.session['password_change_enforce'])
        self.assertFalse(self.client.session['password_is_expired'])
        self.assertFalse(self.client.session['password_is_temporary'])
        self.assertNotContains(resp, 'new_password1')

        # Test if login worked ok
        resp = self.client.get(reverse('login_required_view'), follow=False)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.request['PATH_INFO'], '/')

        # Logout
        resp = self.client.get(reverse('logout'), follow=True)
        self.assertFalse(SESSION_KEY in self.client.session)

        # Move PasswordChange into the past
        period = datetime.timedelta(days=dap_settings.MAX_PASSWORD_AGE)
        expire_at = timezone.now() - period
        pw.timestamp = expire_at
        pw.save()

        # Login will still work
        resp = self.client.post(reverse('login'), data={
            'username': 'rf', 'password': 'password'}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(SESSION_KEY in self.client.session)
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)
        self.assertTrue('password_change_enforce' in self.client.session)
        self.assertTrue(self.client.session['password_change_enforce'])
        self.assertTrue(self.client.session['password_is_expired'])
        self.assertFalse(self.client.session['password_is_temporary'])
        self.assertContains(resp, 'old_password')
        self.assertContains(resp, 'new_password1')
        self.assertContains(resp, 'new_password2')

        # And try requesting a different page still displays a change
        # password view
        resp = self.client.get(reverse('another_view'), follow=False)
        self.assertTrue('password_change_enforce' in self.client.session)
        self.assertTrue(self.client.session['password_change_enforce'])
        self.assertTrue(self.client.session['password_is_expired'])
        self.assertFalse(self.client.session['password_is_temporary'])
        self.assertContains(resp, 'old_password')
        self.assertContains(resp, 'new_password1')
        self.assertContains(resp, 'new_password2')

        # Post a new password
        resp = self.client.post(reverse('login_required_view'), data={
            'old_password': 'password',
            'new_password1': 'abcABC123!@#',
            'new_password2': 'abcABC123!@#'}, follow=True)
        self.assertFalse(self.client.session['password_change_enforce'])
        self.assertFalse(self.client.session['password_is_expired'])
        self.assertFalse(self.client.session['password_is_temporary'])
        self.assertNotContains(resp, 'old_password')
        self.assertNotContains(resp, 'new_password1')
        self.assertNotContains(resp, 'new_password2')
        self.assertEqual(resp.redirect_chain, [('http://testserver/', 302)])

        # Recheck, change password view should be gone
        resp = self.client.get(reverse('login_required_view'), follow=False)
        self.assertNotContains(resp, 'old_password')
        self.assertNotContains(resp, 'new_password1')
        self.assertNotContains(resp, 'new_password2')

        # Logging tests
        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'INFO Authentication success, username=rf, address=127.0.0.1\n'
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'INFO Authentication success, username=rf, address=127.0.0.1\n'
            u'INFO User rf must change expired password\n'
            u'INFO Password change successful for user rf\n'))

    def test_temporary_password(self):
        # Create one recent password change
        PasswordChange.objects.create(user=self.user, successful=True,
                                      is_temporary=True)

        # Login
        resp = self.client.post(reverse('login'), data={
            'username': 'rf', 'password': 'password'})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(SESSION_KEY in self.client.session)
        self.assertEqual(self.client.session[SESSION_KEY], self.user.id)

        # Requesting a page shows password change view
        resp = self.client.get(reverse('login_required_view'), follow=True)
        self.assertEqual(resp.request['PATH_INFO'], '/')
        self.assertContains(resp, 'old_password')
        self.assertContains(resp, 'new_password1')
        self.assertContains(resp, 'new_password2')

        # Change the password:
        resp = self.client.post(reverse('login_required_view'), data={
            'old_password': 'password',
            'new_password1': 'A-New-Passw0rd-4-me',
            'new_password2': 'A-New-Passw0rd-4-me'}, follow=True)
        self.assertEqual(resp.redirect_chain, [('http://testserver/', 302)])
        self.assertEqual(resp.request['PATH_INFO'], '/')
        self.assertNotContains(resp, 'old_password')
        self.assertNotContains(resp, 'new_password1')
        self.assertNotContains(resp, 'new_password2')

        self.assertEqual(PasswordChange.objects.all().count(), 2)
        self.assertEqual(PasswordChange.objects.filter(
            is_temporary=True).count(), 1)

        # Logging tests
        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            u'INFO Authentication attempt, username=rf, address=127.0.0.1\n'
            u'INFO Authentication success, username=rf, address=127.0.0.1\n'
            u'INFO User rf must change temporary password\n'
            u'INFO Password change successful for user rf\n'))

    def password_change_login_required(self):
        resp = self.client.post(reverse('password_change'), follow=True)
        self.assertEqual(resp.redirect_chain, [
            ('http://testserver/login/?next=/password_change/', 302)])

    def test_password_length(self):
        new_passwd = 'Aa1.$Bb2.^Cc.Dd5%.Ee6&.Dd7*'
        short_passwd = new_passwd[:dap_settings.PASSWORD_MIN_LENGTH]

        # Too short password doesnt work
        form = StrictPasswordChangeForm(self.user, data={
            'old_password': 'password',
            'new_password1': short_passwd[:-1],
            'new_password2': short_passwd[:-1]})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors['new_password1'],
                         [form.error_messages['password_min_length']])

        # Longer password does work
        form = StrictPasswordChangeForm(self.user, data={
            'old_password': 'password',
            'new_password1': short_passwd,
            'new_password2': short_passwd})

        self.assertTrue(form.is_valid())

        # Check correct PasswordChange items were created
        self.assertEqual(PasswordChange.objects.all().count(), 2)
        self.assertEqual(PasswordChange.objects.filter(
            successful=True).count(), 1)
        self.assertEqual(PasswordChange.objects.filter(
            successful=False).count(), 1)

        # Logging tests
        self.assertEqual(self.logger.handlers[0].stream.getvalue(), (
            'INFO Password change failed for user rf\n'
            'INFO Password change successful for user rf\n'))

    def test_password_complexity(self):
        # Remove one category at a time to check all posibilities
        rules = collections.deque(dap_settings.PASSWORD_COMPLEXITY)
        for x in xrange(0, len(rules)):
            passwd = u''.join([r['chars'][:4] for r in list(rules)[:-1]])
            form = StrictPasswordChangeForm(self.user, data={
                'old_password': 'password',
                'new_password1': passwd,
                'new_password2': passwd})
            failing_rule = rules[-1]
            self.assertFalse(form.is_valid())
            self.assertEqual(form.errors['new_password1'], [
                form.error_messages['password_complexity'] % failing_rule])

            rules.rotate(1)

    def test_password_differ_old(self):
        """ Make sure new password differs from old password """
        passwd = 'Aa1.$Bb2.^Cc.Dd5%.Ee6&.Dd7*'
        self.user.set_password(passwd)
        self.user.save()

        form = StrictPasswordChangeForm(self.user, data={
            'old_password': passwd,
            'new_password1': passwd,
            'new_password2': passwd})
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors['new_password1'],
                         [form.error_messages['password_unchanged']])
