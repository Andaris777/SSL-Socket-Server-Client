import socket
import time
import configparser
import os

from Extra_features_script import *

'''
socket_server simple example
'''


class SocketServer:
    """
    Class related with socket server object
    """

    def __init__(self):
        """
        Function of initiation of socket server and useful parameters to define it
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

        # Info related to the server

        print(self.color_monitor.background_OKCYAN + '[*] Configuration of the socket server ...\n' +
              self.color_monitor.background_ENDC)

        try:
            self.host = str(config['Server_conf']['server_host'])
            self.port = str(config['Server_conf']['server_port'])
            self.timeout = str(config['Server_conf']['timeout'])
            self.bytelimit = str(config['Server_conf']['bytelimit'])
            self.number_of_canal = str(config['Server_conf']['number_of_canal'])

            # Initiate socket
            self.socket = None

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Missing of Misconfiguration in the config.ini file : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

        # Print server banner
        self.color_monitor.banner_server()

        print(self.color_monitor.background_OKGREEN + '[+] Server configured !\nDisplay of the configured options : \n'
              , 'host : ' + self.host + '\n'
              , 'port : ' + self.port + '\n'
              , 'timeout : ' + self.timeout + '\n'
              , 'byte limit : ' + self.bytelimit + '\n'
              , 'number of canal : ' + self.number_of_canal + '\n')

    def tunnel_com(self):
        """
        Method used to initiate the socket communication from the server
        :return: None
        """
        self.socket = socket.socket()
        self.socket.bind((self.host, int(self.port)))
        self.socket.listen(int(self.number_of_canal))
        self.socket.settimeout(int(self.timeout))

        try:
            connection, address = self.socket.accept()

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] No connection received during the last {} seconds : {}\n'.format(
                    self.timeout, err),
                self.color_monitor.background_ENDC)
            quit()

        print(self.color_monitor.background_OKCYAN + '[*] New connection received from : {} \n'.format(str(address)) +
              self.color_monitor.background_ENDC)

        while True:
            # Received data stream limited to self.bytelimit rate)
            data = connection.recv(int(self.bytelimit)).decode()
            if not data:
                continue
            print(self.color_monitor.background_OKCYAN + '[*] From connected user : {} \n'.format(str(data)) +
                  self.color_monitor.background_ENDC)
            connection.close()
            break


if __name__ == '__main__':
    SocketServerTest = SocketServer()
    SocketServerTest.tunnel_com()
