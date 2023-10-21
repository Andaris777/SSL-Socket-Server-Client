import pdb
import socket
import time
import ssl
import configparser
import os
import warnings

from Extra_features_script import *

'''
socket_client secure simple example
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

            self.folder_SSL_conf = str(config['SSL_conf_CLT']['folder_SSL_conf'])
            self.ca_certs = str(config['SSL_conf_CLT']['ca_certs'])
            self.certfile = str(config['SSL_conf_CLT']['certfile'])
            self.keyfile = str(config['SSL_conf_CLT']['keyfile'])

            # Initiate socket
            self.socket = None
            self.securesocket = None

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Missing of Misconfiguration in the config.ini file : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

        print(
            self.color_monitor.background_OKGREEN + '[+] Server configuration retrieved !\n\n Display of the configured options : \n'
            , '\n --Network and Common Configurations-- \n\n'
            , 'host_server : ' + self.hostserver + '\n'
            , 'port_server : ' + self.portserver + '\n'
            , '\n --SSL Configurations of Client-- \n\n'
            , 'CA_crt : ' + self.ca_certs + '\n'
            , 'SRV_crt : ' + self.certfile + '\n'
            , 'Keyfile : ' + self.keyfile + '\n')

    def send_message(self):
        """
        Method used to send a message
        :return: None
        """

        self.socket = socket.socket()

        # Secure the connection
        print(self.color_monitor.background_OKCYAN +
              '[*] Configuring parameters for secure connexion ...\n' +
              self.color_monitor.background_ENDC)

        try:
            # Create a context
            '''
            # Deprecated
            context = ssl.SSLContext()
            '''

            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True

            # Load the CA certificate used to verify the server certificate
            context.load_verify_locations(cafile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                           self.folder_SSL_conf) + '/' + self.ca_certs))

            # Load the client certificate
            context.load_cert_chain(certfile=str(
                os.path.join((os.path.dirname(os.path.abspath(__name__))), self.folder_SSL_conf) + '/' + self.certfile),
                keyfile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                         self.folder_SSL_conf) + '/' + self.keyfile))

            # Instantiate secure socket
            self.securesocket = context.wrap_socket(self.socket, server_hostname="RD_test.local")

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Cannot connect to the server : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)
            quit()

        # Initiation of connection

        print(self.color_monitor.background_OKCYAN +
              '[*] Trying to connect to remote server ...\n' +
              self.color_monitor.background_ENDC)

        try:
            self.securesocket.connect((self.hostserver, int(self.portserver)))

            ###################################################################
            # Verify if socket is still open or if it broke due to SSL failed #
            # First message to launch the error on server side                #
            # Second, after 1s, to launch error on client side                #
            ###################################################################

            self.securesocket.send(str("Verify open communication").encode())
            time.sleep(1)
            self.securesocket.send(str("Verify open communication").encode())

            # Retrieve server certificate
            server_cert = self.securesocket.getpeercert()

            server_subject = dict(item[0] for item in server_cert['subject'])
            server_CommonName = server_subject['commonName']

            # Check if the client has or not a certificate
            if not server_subject:
                raise Exception("Unable to get the certificate from the client")

            # Check if Common Name issued respect the politic
            if server_CommonName != 'LRTechnologies':
                raise Exception("Incorrect common name in client certificate")

            # Check the validity of the client certificate
            NotBefore = ssl.cert_time_to_seconds(server_cert['notBefore'])
            NotAfter = ssl.cert_time_to_seconds(server_cert['notAfter'])
            ActualTime = time.time()

            if ActualTime < NotBefore:
                raise Exception("Server certificate not yet active")

            if ActualTime > NotAfter:
                raise Exception("Server client certificate deprecated")

            print(
                self.color_monitor.background_OKGREEN + '[+] Secure connection establish !!!\n' + self.color_monitor.background_ENDC)

            ##########################
            # retrieve message to send
            ##########################

            message = input("Message to send -> ")

            print("\n")
            # send message
            self.securesocket.send(message.encode())

            # close connection
            self.securesocket.close()
            self.socket.close()


        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Cannot connect to the server : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

            # close connection
            self.securesocket.close()
            self.socket.close()

            quit()


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    ClientSocketTest = SocketClient()
    ClientSocketTest.send_message()
