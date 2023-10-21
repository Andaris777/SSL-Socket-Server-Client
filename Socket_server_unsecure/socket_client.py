import socket
import time
import configparser
import os

from Extra_features_script import *

'''
socket_client simple example
'''


class SocketClient:
    """
    Class related with socket client object
    """

    def __init__(self):
        """
        Function of initiation of client server and useful parameters to define it
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

        # Print server banner
        self.color_monitor.banner_client()

        # Info related to the server which the client shall connect to

        print(self.color_monitor.background_OKCYAN + '[*] Retrieving configuration of the socket server ...\n' +
              self.color_monitor.background_ENDC)

        try:
            self.hostserver = str(config['Server_conf']['server_host'])
            self.portserver = str(config['Server_conf']['server_port'])

            # Initiate socket
            self.socket = None

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Missing of Misconfiguration in the config.ini file : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

        print(
            self.color_monitor.background_OKGREEN + '[+] Server configuration retrieved !\nDisplay of the configured options : \n'
            , 'host : ' + self.hostserver + '\n'
            , 'port : ' + self.portserver + '\n')

    def send_message(self):
        """
        Method used to send a message
        :return: None
        """

        self.socket = socket.socket()

        try:
            self.socket.connect((self.hostserver, int(self.portserver)))

            # retrieve message to send
            message = input("Message to send -> ")

            print("\n")

            # send message
            self.socket.send(message.encode())

            # close connection
            self.socket.close()

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Cannot connect to the server : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)
            quit()


if __name__ == '__main__':
    ClientSocketTest = SocketClient()
    ClientSocketTest.send_message()
