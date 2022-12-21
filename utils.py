#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)


from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from flask import current_app, jsonify, request
from errors import AuthorizationError, InvalidArgumentError
from crayons import red,green,yellow,blue,cyan



def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    # added pprint to trace token arriving from POST
    print(blue(f'authentcation in GET_JWT ={token}'))
    try:
#    NOW ADD FUNCTION TO DECODE JWT AND SECRET PATRICKS VIDEO
      result = (jwt.decode(token,'JEQ3o2Vw0kQnQdG3dekOvEdI7NYEqov0DJGSAyDkhopfy1eUgDIIhTOVNyj5UO31')['key'])
      print((f'Cyber Vision Token is: ', {result}))
    #   NOW CHECK FOR MATCH INSIDE THE APP ROUTE
      return (result)
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    data = request.get_json(force=True, silent=True, cache=False)

    '''
    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)
    '''
    return data


def jsonify_data(data):
    return jsonify({'data': data})

def jsonify_errors(data):
    return jsonify({'errors': [data]})
