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
