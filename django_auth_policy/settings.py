"""
Django Authentication Policy - Default settings

Warning: lockout of usernames or IP addresses based on number of failed login
attempts can be used by attackers to temporarily lock out valid users.

Alter the settings by adding them to your projects settings file, do not edit
the defaults below.
"""
from django.conf import settings
from django.utils.translation import ugettext as _

# Number of days after which the user is required to change their password
# Set to None to disable this feature
MAX_PASSWORD_AGE = getattr(settings, 'MAX_PASSWORD_AGE', 30)

# By default a password change is enforced when a user has no password change
# history
ALLOW_EMPTY_PASSWORD_HISTORY = getattr(settings,
                                       'ALLOW_EMPTY_PASSWORD_HISTORY', False)

# Number of days without a successful log-in after which a user will be
# disabled. Set to None to disable this feature
INACTIVE_USERS_EXPIRY = getattr(settings, 'INACTIVE_USERS_EXPIRY', 90)

# Number of failed authentications for a specific username within the
# FAILED_AUTH_PERIOD that triggers a lockout (for a 'three strikes and you're
# out' policy)
# Set to None to disable this feature
FAILED_AUTH_USERNAME_MAX = getattr(settings, 'FAILED_AUTH_USERNAME_MAX', 3)

# Number of failed authentications for a specific remote address within the
# FAILED_AUTH_PERIOD that triggers a lockout (for a 'three strikes and you're
# out' policy)
# Set to None to disable this feature
FAILED_AUTH_ADDRESS_MAX = getattr(settings, 'FAILED_AUTH_ADDRESS_MAX', 3)

# Period used to measure the number of failed logins, in seconds
# Set to None to count all failed logins that count towards a lockout
# (Set to None by default)
FAILED_AUTH_PERIOD = getattr(settings, 'FAILED_AUTH_PERIOD', None)

# Failed authentication lockout period in seconds, the default is 3 hours
FAILED_AUTH_LOCKOUT_PERIOD = getattr(settings, 'FAILED_AUTH_LOCKOUT_PERIOD',
                                     60 * 60 * 3)

# Minimum password length requirement
PASSWORD_MIN_LENGTH = getattr(settings, 'PASSWORD_MIN_LENGTH', 10)

# Minimum password length text
if PASSWORD_MIN_LENGTH:
    PASSWORD_MIN_LENGTH_TEXT = getattr(settings, 'PASSWORD_MIN_LENGTH_TEXT', _(
        'Passwords must be at least %d characters in length.')
        % PASSWORD_MIN_LENGTH)
else:
    PASSWORD_MIN_LENGTH_TEXT = ''

# Additional password strength requirements
# Define a list of character requirements, each requirement defines:
# - 'name': Name of the character class
# - 'chars': string with all characters of that class
# - 'min': minimum number of characters required from this class
# - 'text': a text explaining the complexity rule
#   This text might be prepended with something like: 'Passwords must have',
#   and might be appended with the available characters (between parentheses)
#   Example: Passwords must have at least ... (abcdefghijklmnopqrstuvwxyz)
# Set the whole setting to None to disable additional strength requirements
PASSWORD_COMPLEXITY = getattr(settings, 'PASSWORD_COMPLEXITY', (
    {'name': _('lowercase characters'),
     'chars': 'abcdefghijklmnopqrstuvwxyz',
     'min': 1,
     'text': _('at least one lowercase character')},

    {'name': _('uppercase characters'),
     'chars': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
     'min': 1,
     'text': _('at least one uppercase character')},

    {'name': _('numbers'),
     'chars': '0123456789',
     'min': 1,
     'text': _('at least one number')},

    {'name': _('symbols'),
     'chars': '!@#$%^&*()_+-={}[]:;"\'|\\,.<>?/~`',
     'min': 1,
     'text': _('at least one symbol')},
    ))

# Characters used to generate temporary passwords
TEMP_PASSWORD_CHARS = getattr(settings, 'TEMP_PASSWORD_CHARS',
                              'abcdefghijlkmnopqrstuvwxyz'
                              'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                              '0123456789')

# Temporary password length
TEMP_PASSWORD_LENGTH = getattr(settings, 'TEMP_PASSWORD_LENGTH', 12)

# django_auth_policy replaces the default Django auth UserAdmin to enforce
# authentication policies on the admin interface. Set this to False when
# django_auth_policy shouldn't replace UserAdmin.
REPLACE_AUTH_USER_ADMIN = getattr(settings, 'REPLACE_AUTH_USER_ADMIN', True)
