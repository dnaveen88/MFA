class UserManagement():
    """
    UserManagement class for managing user-related operations.

    This class provides methods for creating, updating, retrieving, and deleting users.

    Methods:
        - update_user: Update user information.
        - get_user: Retrieve user information.
        - delete_user: Delete a user.
    """

    def perform_login(self, username, password, user_ip_address):
        """
        Validate user credentials on server.
        """
        failed_login_ip_obj = FailedLoginIPList.objects.filter(ipv4_addr=user_ip_address).first()
        if failed_login_ip_obj is not None and failed_login_ip_obj.consecutive_failed_login_cnt == \
                                constants.FAILED_IP_MAX_COUNT:
            raise PermissionException(f"{user_ip_address} is blocked")
        whitelisting_ips = IPWhiteList.objects.filter(ipv4_addr=user_ip_address).exists()
        db_username = username+constants.OSI_EMAIL_DOMAIN
        queryset = User.objects.filter(username=db_username).first()
        resp = {}
        action_type = constants.LOGIN_FAILED
        status_code = 401
        domain = constants.USER_DOMAIN
        sc_id = None
        performed_by_user_id = None
        performed_by_ad_username = None

        if queryset:
            sc_id = queryset.id
            performed_by_ad_username = username
            performed_by_user_id = queryset.id
            if queryset.deleted_at is not None:
                action_type = constants.INACTIVE_DIGITALVUE_ACCOUNT
                resp = {"errorMessage": "User in inactive state."}
                create_log(constants.LOGIN_DOMAIN, action_type, performed_by_user_id,
                        performed_by_ad_username, None, None, None, None,
                        None, None, queryset.id, user_ip_address)
                # login count is increasing in failed ip
                utils.failed_login_ip_address(user_ip_address,
                                              whitelisting_ips, failed_login_ip_obj)
            else:
                response, status_code = utils.remaining_wait_time(db_username, user_ip_address)
                if status_code != 200:
                    action_type = constants.LOGIN_RESTRICTED

                    return response, status_code

                # Check username, password on server
                _authentication = self.validate_server_credentials(username, password)
                if _authentication:
                    mfa_device = self.create_or_fetch_device(queryset)
                    qr_code_resp = None

                    if mfa_device and not mfa_device.confirmed:
                        qr_code_resp = self.generate_qrcode(mfa_device, performed_by_user_id,
                                                db_username, user_ip_address)

                    queryset.primary_verification_status = True
                    queryset.save()
                    user = UserSerializer(queryset, many=False).data

                    user["MFA Device"] = {
                        "id": mfa_device.pk if mfa_device else None,
                        "qr_image": qr_code_resp
                    }

                    # Adding first name and last name here from contact
                    # Not changing UserSerializer as it is used elsewhere
                    contact_id = int(user.get("contact"))
                    contact = Contact.objects.get(pk=contact_id)
                    user["first_name"] = contact.first_name
                    user["last_name"] = contact.last_name
                    time_zone = None
                    if contact.time_zone:
                        time_zone = TimeZone.objects.filter(id=contact.time_zone.id).first()
                    user["time_zone_name"] = time_zone.name if time_zone else None
                    user["time_zone_code"] = time_zone.code if time_zone else None
                    user["time_zone_utc_offset"] = time_zone.utc_offset if time_zone else None
                    status_code = 200
                    resp = user
                    if not whitelisting_ips:
                        if failed_login_ip_obj is None:
                            FailedLoginIPList.objects.create(ipv4_addr=user_ip_address,
                                            consecutive_failed_login_cnt=0)
                        else:
                            failed_login_ip_obj.consecutive_failed_login_cnt = 0
                            failed_login_ip_obj.save()

                    return resp, status_code
                else:
                    action_type = constants.INVALID_USER_PASS
                    system_user_obj = User.objects.get(username="system")
                    system_user_id = system_user_obj.id
                    create_log(domain, action_type, None, db_username, None, None, None, None,
                        None, None, system_user_id, user_ip_address)
                    wait_time_response, status_code = utils.wait_time(db_username, user_ip_address)
                    resp = wait_time_response
        else:
            # Failed Login Attempt added to Block Listing IP
            action_type = constants.INVALID_USER_PASS
            domain = constants.LOGIN_DOMAIN
            system_user_obj = User.objects.get(username="system")
            system_user_id = system_user_obj.id
            create_log(domain, action_type, None, db_username, None, None, None, None,
                        None, None, system_user_id, user_ip_address)
            utils.failed_login_ip_address(user_ip_address, whitelisting_ips, failed_login_ip_obj)

            resp = {"errorMessage": "Entry restricted for login only."}

        if failed_login_ip_obj is not None and failed_login_ip_obj.consecutive_failed_login_cnt == constants.FAILED_IP_MAX_COUNT:
            domain = constants.LOGIN_DOMAIN
            action_type = constants.IPADDRESS_BLOCKED
            create_log(domain, action_type, None, None, None, None, None, None,
                        None, None, system_user_id, user_ip_address)
        return resp, status_code
