import datetime
import logging

from django.utils import timezone
from django.contrib.auth import get_user_model

from django_auth_policy import settings as dap_settings
from django_auth_policy import signals
from django_auth_policy.models import LoginAttempt, PasswordChange


logger = logging.getLogger(__name__)


def disable_expired_users():
    """ Disable users that have been expired

    Run inside the authentication form or backend,
    and before calling django.contrib.auth.login

    Returns a list with the primary keys of the disabled users.

    Reactivate user by setting is_active to True and last_login to now.
    """
    if dap_settings.INACTIVE_USERS_EXPIRY is None:
        return None

    expire_at = timezone.now() - datetime.timedelta(
        days=dap_settings.INACTIVE_USERS_EXPIRY)

    expired = get_user_model().objects.filter(is_active=True,
                                              last_login__lt=expire_at)

    for user in expired:
        logger.warning('User %s disabled because last login was at %s',
                       user.username, user.last_login)
        # Send signal to be used to alert admins
        signals.user_expired.send(sender=user, user=user)

    user_ids = list(expired.values_list('pk', flat=True))

    expired.update(is_active=False)

    return user_ids


def locked_username(username):
    """ Returns whether username is locked-out
    """
    if dap_settings.FAILED_AUTH_USERNAME_MAX is None:
        return False

    try:
        last_login = LoginAttempt.objects.filter(username=username
                                                 ).order_by('-id')[0]
    except IndexError:
        # No login attempts for this username and thus no lockout
        return False

    user_lockout = LoginAttempt.objects.filter(username=username,
                                               successful=False,
                                               lockout=True)
    if dap_settings.FAILED_AUTH_PERIOD is not None:
        lockout_count_from = timezone.now() - datetime.timedelta(
            seconds=dap_settings.FAILED_AUTH_PERIOD)
        user_lockout = user_lockout.filter(timestamp__gt=lockout_count_from)

    return (user_lockout.count() >= dap_settings.FAILED_AUTH_USERNAME_MAX and
            last_login.within_lockout_period)


def locked_remote_addr(remote_addr):
    """ Returns whether remote address is locked-out
    """
    if dap_settings.FAILED_AUTH_ADDRESS_MAX is None:
        return False

    # Lock per IP address
    try:
        last_login = LoginAttempt.objects.filter(
            source_address=remote_addr).order_by('-id')[0]
    except IndexError:
        # No previous login attempts for this IP address and thus no lockout
        return False

    ip_lockout = LoginAttempt.objects.filter(source_address=remote_addr,
                                             lockout=True)
    if dap_settings.FAILED_AUTH_PERIOD is not None:
        lockout_count_from = timezone.now() - datetime.timedelta(
            seconds=dap_settings.FAILED_AUTH_PERIOD)
        ip_lockout = ip_lockout.filter(timestamp__gt=lockout_count_from)

    return (ip_lockout.count() >= dap_settings.FAILED_AUTH_ADDRESS_MAX and
            last_login.within_lockout_period)


def enforce_password_change(user):
    """ Checks if the user must change its password

    Returns a tuple with three booleans:
    * password change is required;
    * current password has expired;
    * current password is temporary;
    """
    enforce_change = False
    is_expired = False
    is_temporary = False
    # Retrieve last successful password change for user
    try:
        last_pw_change = PasswordChange.objects.filter(
            user=user, successful=True).order_by('-id')[0]
    except IndexError:
        # No password changes recorded
        # Enforce a password change when user has no PasswordChange
        enforce_change = not dap_settings.ALLOW_EMPTY_PASSWORD_HISTORY

        return (enforce_change, is_expired, is_temporary)

    # Enforce temporary password change
    if last_pw_change.is_temporary:
        enforce_change = True
        is_temporary = True

    # Enforce password expiry policy
    if dap_settings.MAX_PASSWORD_AGE is not None:

        expire_at = last_pw_change.timestamp + datetime.timedelta(
            days=dap_settings.MAX_PASSWORD_AGE)

        if timezone.now() > expire_at:
            enforce_change = True
            is_expired = True

    return (enforce_change, is_expired, is_temporary)
