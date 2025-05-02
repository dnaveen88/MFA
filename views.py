@api_view(['POST',])
def do_login(request):
    """
    This method for validating the user authentication.
    """
    try:
        username = utils.decrypt(request.data['userName']).lower()
        password = utils.decrypt(request.data['password'])
        user_ip_address = utils.get_ip_address(request)
        user, status_code = user_management.perform_login(username, password, user_ip_address)
        return JsonResponse(user, status= status_code, safe=False)

    except Exception as err:
        raise err
