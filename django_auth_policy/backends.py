""" The authentication backend below work just like Djangos Auth backend but
also enforce locked usernames and disables expired users.

WARNING: this backend does NOT enforce locked IP addresses. Always use the
Django Auth Policy forms for proper policy enforcements and customized error
messages. The backend below is just an extra layer of protection in case a
certain view still uses the default Django AuthenticationForm, by accident.
"""
from django.contrib.auth.backends import ModelBackend

from django_auth_policy.checks import disable_expired_users, locked_username


class StrictModelBackend(ModelBackend):
    def authenticate(self, username=None, password=None, **kwargs):
        if username and locked_username(username):
            return None

        user = super(StrictModelBackend, self
                     ).authenticate(username=username, password=password,
                                    **kwargs)

        if user is not None and user.is_authenticated():
            disabled_pks = disable_expired_users()
            if user.pk in disabled_pks:
                user.is_active = False

        return user
