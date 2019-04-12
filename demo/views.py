import json
import os
import requests
from http.cookies import SimpleCookie

from django.conf import settings
from django.urls import reverse
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)
from django.shortcuts import render

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
    return auth


def get_port(request):
    if settings.USE_X_FORWARDED_PORT and 'HTTP_X_FORWARDED_PORT' in request.META:
        port = request.META['HTTP_X_FORWARDED_PORT']
    else:
        port = request.META['SERVER_PORT']
    return port


def prepare_django_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    result = {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': get_port(request),
        'get_data': request.GET.copy(),
        'lowercase_urlencoding': True,
        'post_data': request.POST.copy()
    }
    return result


def index(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    # single sign on
    if 'sso' in req['get_data']:
        return HttpResponseRedirect(auth.login())
    # single sign on 2
    elif 'sso2' in req['get_data']:
        return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
        return HttpResponseRedirect(auth.login(return_to='/'))
    # single log out
    elif 'slo' in req['get_data']:
        name_id = None
        session_index = None
        if 'samlNameId' in request.session:
            name_id = request.session['samlNameId']
        if 'samlSessionIndex' in request.session:
            session_index = request.session['samlSessionIndex']

        return HttpResponseRedirect(auth.logout(name_id=name_id, session_index=session_index))
    # attribute consumer service
    elif 'acs' in req['get_data']:
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if not errors:
            request.session['samlUserdata'] = auth.get_attributes()
            request.session['samlNameId'] = auth.get_nameid()
            request.session['samlSessionIndex'] = auth.get_session_index()
            if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))
        else:
            if auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
    # single logout service
    elif 'sls' in req['get_data']:
        dscb = lambda: request.session.flush()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return HttpResponseRedirect(url)
            else:
                success_slo = True
    # logged in
    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            # get university SAML attributes 
            attributes = request.session['samlUserdata'].items()
            attr_dict = request.session['samlUserdata']
            # make request to python server
            response = requests.post('https://aswwu.com/server/verify', {
                'secret_key': os.getenv('SAML_KEY'),
                'employee_id': attr_dict['employee_id'],
                'full_name': attr_dict['full_name'],
                'email_address': attr_dict['email_address']
            })
            cookies = response.headers['Set-Cookie'].split('; ')
            cookie_dict = {}
            for c in cookies:
                s = c.split('=')
                cookie_dict[s[0].lower()] = s[1]
            print(cookie_dict)
            response = HttpResponseRedirect('https://aswwu.com')
            response.set_cookie('token', cookie_dict['token'], domain=cookie_dict['domain'], expires=cookie_dict['expires'], path=cookie_dict['path'])
            return response
    # page render
    return render(request, 'index.html', {'errors': errors, 'error_reason': error_reason, 'not_auth_warn': not_auth_warn, 'success_slo': success_slo,
                                          'attributes': attributes, 'paint_logout': paint_logout})


def attrs(request):
    paint_logout = False
    attributes = False

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()
    return render(request, 'attrs.html',
                  {'paint_logout': paint_logout,
                   'attributes': attributes})


def metadata(request):
    # req = prepare_django_request(request)
    # auth = init_saml_auth(req)
    # saml_settings = auth.get_settings()
    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=settings.SAML_FOLDER, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type='text/xml')
    else:
        resp = HttpResponseServerError(content=', '.join(errors))
    return resp
