import logging
try:
    from collections import OrderedDict
except ImportError:
    # python 2.6 or earlier, use backport
    from ordereddict import OrderedDict

from django import forms
from django.utils.translation import ugettext as _
from django.contrib.auth import authenticate
from django.contrib.auth.forms import (AuthenticationForm, SetPasswordForm,
                                       PasswordChangeForm)

from django_auth_policy.models import PasswordChange, LoginAttempt
from django_auth_policy import settings as dap_settings
from django_auth_policy.checks import (disable_expired_users, locked_username,
                                       locked_remote_addr)


logger = logging.getLogger(__name__)


class StrictAuthenticationForm(AuthenticationForm):

    error_messages = dict(AuthenticationForm.error_messages, **{
        'username_locked_out': _('Your account has been locked. Contact your '
                                 'user administrator for more information.'),
        'address_locked_out': _('Your account has been locked. Contact your '
                                'user administrator for more information.')})

    def __init__(self, request, *args, **kwargs):
        """ Make request argument required
        """
        return super(StrictAuthenticationForm, self).__init__(request, *args,
                                                              **kwargs)

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        remote_addr = self.request.META['REMOTE_ADDR']

        logger.info('Authentication attempt, username=%s, address=%s',
                    username, remote_addr)

        if not username and not password:
            return self.cleaned_data

        attempt = LoginAttempt(
            username=username,
            source_address=remote_addr,
            hostname=self.request.get_host()[:100],
            successful=False,
            lockout=True)

        if not username:
            logger.warning(u'Authentication failure, address=%s, '
                           'no username supplied.',
                           remote_addr)
            attempt.save()
            return self.cleaned_data

        if not password:
            logger.warning(u'Authentication failure, username=%s, '
                           'address=%s, no password supplied.',
                           username, remote_addr)
            attempt.save()
            return self.cleaned_data

        if locked_username(username):
            logger.warning(u'Authentication failure, username=%s, address=%s, '
                           'username locked', username, remote_addr)
            attempt.save()
            raise forms.ValidationError(
                self.error_messages['username_locked_out'],
                'username_locked_out')

        if locked_remote_addr(remote_addr):
            logger.warning(u'Authentication failure, username=%s, address=%s, '
                           'address locked', username, remote_addr)
            attempt.save()
            raise forms.ValidationError(
                self.error_messages['address_locked_out'],
                'address_locked_out')

        disable_expired_users()
        self.user_cache = authenticate(username=username,
                                       password=password)
        if self.user_cache is None:
            logger.warning(u'Authentication failure, username=%s, '
                           'address=%s, invalid authentication.',
                           username, remote_addr)
            attempt.save()
            raise forms.ValidationError(
                self.error_messages['invalid_login'] % {
                    'username': self.username_field.verbose_name},
                code='invalid_login')

        if not self.user_cache.is_active:
            logger.warning(u'Authentication failure, username=%s, '
                            'address=%s, user inactive.',
                            username, remote_addr)
            attempt.save()
            raise forms.ValidationError(
                self.error_messages['inactive'],
                code='inactive')

        # Authentication was successful
        logger.info(u'Authentication success, username=%s, address=%s',
                    username, remote_addr)
        attempt.successful = True
        attempt.lockout = False
        attempt.user = self.user_cache
        attempt.save()

        # Reset lockout counts for IP address and username
        LoginAttempt.objects.filter(username=username,
                                    lockout=True).update(lockout=False)
        LoginAttempt.objects.filter(source_address=remote_addr,
                                    lockout=True).update(lockout=False)

        return self.cleaned_data


class StrictSetPasswordForm(SetPasswordForm):
    error_messages = dict(PasswordChangeForm.error_messages, **{
        'password_min_length': dap_settings.PASSWORD_MIN_LENGTH_TEXT,
        'password_complexity': _("Passwords must have %(text)s")
        })

    def clean_new_password1(self):
        pw = self.cleaned_data.get('new_password1')
        if not pw:
            return pw

        # Minimum password length check
        if (dap_settings.PASSWORD_MIN_LENGTH is not None and
                len(pw) < dap_settings.PASSWORD_MIN_LENGTH):

            raise forms.ValidationError(
                self.error_messages['password_min_length'],
                'password_min_length')

        # Password complexity check
        if dap_settings.PASSWORD_COMPLEXITY is not None:
            pw_set = set(pw)
            for rule in dap_settings.PASSWORD_COMPLEXITY:
                if not pw_set.intersection(rule['chars']):
                    raise forms.ValidationError(
                        self.error_messages['password_complexity'] % rule,
                        'password_complexity')

        return pw

    def is_valid(self):
        valid = super(StrictSetPasswordForm, self).is_valid()
        if self.is_bound:
            PasswordChange.objects.create(user=self.user, successful=valid,
                                          is_temporary=False)
            if valid:
                logger.info('Password change successful for user %s', self.user)
            else:
                logger.info('Password change failed for user %s', self.user)

        return valid


class StrictPasswordChangeForm(StrictSetPasswordForm, PasswordChangeForm):
    error_messages = dict(StrictSetPasswordForm.error_messages, **{
        'password_unchanged': _("The new password must not be the same as "
                                "the old password"),
        })

    def clean_new_password1(self):
        pw = super(StrictPasswordChangeForm, self).clean_new_password1()

        # Check that old and new password differ
        if (self.cleaned_data.get('old_password') and
                self.cleaned_data['old_password'] == pw):

            raise forms.ValidationError(
                self.error_messages['password_unchanged'],
                'password_unchanged')

        return pw

StrictPasswordChangeForm.base_fields = OrderedDict(
    (k, StrictPasswordChangeForm.base_fields[k])
    for k in ['old_password', 'new_password1', 'new_password2']
)
