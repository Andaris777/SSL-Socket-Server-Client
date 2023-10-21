import os
import json
import hashlib
import configparser

from Extra_features_script import *


class LoginMonitor:
    """
    Class related to the management of the user/password provided by the user.
    """

    def __init__(self):
        """
        Function of initiation of login monitor and useful parameters to define it
        :param self:
        :return: None
        """

        # Background color monitor################
        self.color_monitor = Background_printer()
        ##########################################

        # Initiate the config file################
        config = configparser.ConfigParser()
        ##########################################

        try:
            config.read(os.path.join((os.path.dirname(os.path.abspath(__name__))), 'config.ini'))
        except FileExistsError as err:
            print(self.color_monitor.background_FAIL + '[x] File .ini does not exist : {}\n'.format(err),
                  self.color_monitor.background_ENDC)

        # Define recipient of useful parameters
        try:
            # Define database localisation information
            self.db_folder = str(config['Login_Monitor']['folder_db'])
            self.db_file = str(config['Login_Monitor']['file_db'])

            # Define flag
            self.wrong_username_flag = None
            self.wrong_password_flag = None


        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Missing of Misconfiguration in the config.ini file : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

    def login(self, username_to_log_with, password_to_log_with):
        """
        Function which define the login method
        :param self:
        :return: 0 if everything goes right ; Exception if error
        """
        #####################
        # Initiate DataBase #
        #####################

        # Database file read

        try:
            path_to_database = str(
                os.path.join((os.path.dirname(os.path.abspath(__name__))), self.db_folder) + '/' + self.db_file)

            with open(path_to_database) as json_db_data:
                data_login = json.load(json_db_data)

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Missing of database file : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

        # Parse the user/password
        dict_user_password = {}

        for id in data_login.keys():
            dict_user_password[str(data_login[id]['user'])] = str(data_login[id]['hash'])

        # Check login
        try:
            # Check username
            for user in dict_user_password.keys():
                if user == username_to_log_with:
                    print(
                        self.color_monitor.background_OKBLUE + '[*!*] User : {} \n'.format(
                            username_to_log_with) + self.color_monitor.background_ENDC)

                    # Set flag wrong username to False
                    self.wrong_username_flag = False

            # Check if wrong username flag is None. In that case user provided does not exist
            if self.wrong_username_flag is None:
                raise Exception("Wrong username")

            # Check password

            # SHA512 the provided password
            hash_password_to_log_with = hashlib.sha512(str(password_to_log_with).encode()).hexdigest()

            # Check if password provided is right or wrong
            if hash_password_to_log_with == dict_user_password[username_to_log_with]:
                print(
                    self.color_monitor.background_OKBLUE + '[*!*] Right password \n'
                    + self.color_monitor.background_ENDC)

                # Set flag wrong password to False
                self.wrong_password_flag = False

            if self.wrong_password_flag is None:
                raise Exception("Wrong password")

            return 0

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Error the connexion : {} \n'.format(
                    err),
                self.color_monitor.background_ENDC)
            return err
