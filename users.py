class UserManagement():
    """
    UserManagement class for managing user-related operations.

    This class provides methods for creating, updating, retrieving, and deleting users.


    Methods:
        - update_user: Update user information.
        - get_user: Retrieve user information.
        - delete_user: Delete a user.
    """

    def update_last_generation_time(self, current_time):
        """
        Update the last generation time.
        """
        self._last_generation_time = current_time

    def generate_qrcode(self, device, user_id, username, user_ip_address):
        """
         To get the qr code image link every 120 seconds and manage last generation time
        """
        current_time = datetime.now()
        seconds = constants.SECONDS

        # Check if 120 seconds have passed since the last generation or if it's the first time
        action_type = None
        if self._last_generation_time is None or \
            (current_time - self._last_generation_time) > timedelta(seconds=seconds):

            # Update the key attribute every 120 seconds
            device.key = self.generate_new_key()
            device.save()

            # Generate QR code image
            qr_code_img = qrcode.make(device.config_url)
            buffer = BytesIO()
            qr_code_img.save(buffer)
            buffer.seek(0)
            encoded_img = b64encode(buffer.read()).decode()
            qr_code_data = f'data:image/png;base64,{encoded_img}'

            if self._last_generation_time is None:
                action_type = constants.DISPLAY_QR
            else:
                action_type = constants.REFRESH_QR

            # Update the last generation time
            self.update_last_generation_time(current_time)
        else:
            # If less than 120 seconds have passed, return None and
            # the existing last generation time
            return None
        if action_type is not None:
            domain = constants.MFA_DOMAIN
            create_log(domain, action_type, user_id, username, None, None, None, None,
                        None, None, user_id, user_ip_address)
        return qr_code_data

    def generate_new_key(self):
        """
        Function to generate a new key for TOTPDevice
        This function should generate a new key every 30 seconds
        """        
        new_key = secrets.token_hex(20)
        
        return new_key


def remaining_wait_time(username, user_ip_address):
    """
    Check if the user account should be temporarily locked due to repeated failed login attempts.

    Parameters:
    - username (str): The username of the user for whom to check the wait time.

    Returns:
    - dict: A dictionary containing information about the wait time or a message to continue.
    """

    user = User.objects.get(username=username)
    if user.consecutive_failed_login_cnt > 5:
        domain = constants.USER_DOMAIN
        action_type = constants.USER_LOCKED
        system_user_obj = User.objects.get(username="system")
        system_user_id = system_user_obj.id
        create_log(domain, action_type, user.id, user.username, None, None, None, None,
                None, None, system_user_id, user_ip_address)
        whitelisting_ips = IPWhiteList.objects.filter(ipv4_addr=user_ip_address).exists()
        if not whitelisting_ips:
            failed_login_ip_obj, _ = FailedLoginIPList.objects.get_or_create(ipv4_addr=user_ip_address)
            #incrementing consecutive login count for the IP address
            failed_login_ip_obj.consecutive_failed_login_cnt += 1
            failed_login_ip_obj.save()
        if failed_login_ip_obj.consecutive_failed_login_cnt == constants.FAILED_IP_MAX_COUNT:
            domain = constants.LOGIN_DOMAIN
            action_type = constants.IPADDRESS_BLOCKED
            create_log(domain, action_type, None, None, None, None, None, None,
                        None, None, system_user_id, user_ip_address)
        return {'errorMessage': 'Account is locked. Please contact the OSI Help Desk.'}, 423
    
    if user.consecutive_failed_login_cnt > 0:
        elapsed_time = timezone.now() - user.last_login_failed_at
        user_wait_time = {1: 1, 2: 2, 3: 4, 4: 8, 5: 20}
        remaining_time = user_wait_time[user.consecutive_failed_login_cnt] * 15 - elapsed_time.seconds
        remaining_minutes = seconds_to_minutes(remaining_time)
        if remaining_time > 0:
            return {'errorMessage': f'Login Failed. Please try after {remaining_minutes}',
                    'remaining_seconds': remaining_time}, 429
    return {'message': 'continue'}, 200
def wait_time(username, user_ip_address):
    """
    Handles failed login attempts and calculates the wait time for subsequent attempts.

    Args:
        failed_login_response (dict): The response to be returned for a failed login attempt.
        username (str): The username associated with the login attempt.
        user_ip_address (str): The IP address of the user attempting to log in.

    Returns:
        tuple: A tuple containing a dictionary with either the error message or the wait time
               and the corresponding HTTP status code.
    """
    # Add consecutive failed login count into FailedLoginIPList table.
    system_user_obj = User.objects.get(username="system")
    system_user_id = system_user_obj.id
    whitelisting_ips = IPWhiteList.objects.filter(ipv4_addr=user_ip_address).exists()
    if not whitelisting_ips:
        failed_login_ip_obj, _ = FailedLoginIPList.objects.get_or_create(ipv4_addr=user_ip_address)
        failed_login_ip_obj.consecutive_failed_login_cnt += 1
        failed_login_ip_obj.save()
    failed_login_ip_obj = FailedLoginIPList.objects.filter(ipv4_addr=user_ip_address).first()
    if failed_login_ip_obj is not None and failed_login_ip_obj.consecutive_failed_login_cnt == constants.FAILED_IP_MAX_COUNT:
        domain = constants.LOGIN_DOMAIN
        action_type = constants.IPADDRESS_BLOCKED
        create_log(domain, action_type, None, None, None, None, None, None,
                    None, None, system_user_id, user_ip_address)
    user= User.objects.get(username=username)
    user.consecutive_failed_login_cnt = user.consecutive_failed_login_cnt+1
    user.last_login_failed_at = timezone.now()
    user.save()
    user_wait_time = {1: 1, 2: 2, 3: 4, 4: 8, 5: 20}
    if user.consecutive_failed_login_cnt > 5:
        resp = {'errorMessage': \
                'Account is locked. Please contact the OSI Help Desk.'}
        domain = constants.USER_DOMAIN
        action_type = constants.USER_LOCKED
        create_log(domain, action_type, user.id, user.username, None, None, None, None, 
                   None, None, system_user_id, user_ip_address)
        status_code = 423
    else:
        remaining_seconds = 15 * user_wait_time[user.consecutive_failed_login_cnt]
        remaining_minutes = seconds_to_minutes(remaining_seconds)
        resp = {'errorMessage': \
                f'Login Failed. Please try after {remaining_minutes}',
                'remaining_seconds': remaining_seconds}
        status_code = 429
    return resp, status_code
