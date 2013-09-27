#!/usr/bin/env python
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

if __name__ == "__main__":
    os.environ["DJANGO_SETTINGS_MODULE"] = "django_auth_policy.tests.settings"

    from django.core import management

    management.call_command('test', 'django_auth_policy', verbosity=1,
                            interactive=False)
