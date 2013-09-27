import logging

from django.conf import settings
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.utils.http import is_safe_url
from django.shortcuts import resolve_url
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

# Avoid shadowing the login() view below.
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.sites.models import get_current_site

from django_auth_policy.forms import StrictAuthenticationForm
from django_auth_policy.checks import enforce_password_change


logger = logging.getLogger(__name__)


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name='registration/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=StrictAuthenticationForm,
          current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.

    Uses the StrictAuthenticationForm and triggers a password change after
    login when required.
    """
    redirect_to = request.REQUEST.get(redirect_field_name, '')

    if request.method == "POST":
        form = authentication_form(request, data=request.POST)
        if form.is_valid():

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            # Okay, security check complete. Log the user in.
            auth_login(request, form.get_user())

            # Check for temporary or expired passwords and store in session
            # The middleware should enforce a password change in next request
            enforce, is_exp, is_temp = enforce_password_change(form.get_user())
            request.session['password_change_enforce'] = enforce
            request.session['password_is_expired'] = is_exp
            request.session['password_is_temporary'] = is_temp

            # Log password enforcement
            if enforce:
                if is_temp:
                    logger.info(u'User %s must change temporary password',
                                request.user)
                if is_exp:
                    logger.info(u'User %s must change expired password',
                                request.user)
                if not is_temp and not is_exp:
                    logger.info(u'User %s must change password',
                                request.user)

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)
