import socket
import time
import ssl
import configparser
import os
import warnings

from Extra_features_script import *

'''
socket_server secure simple example
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

        # Print server banner
        self.color_monitor.banner_server()

        # Info related to the server

        print(self.color_monitor.background_OKCYAN + '[*] Configuration of the socket server ...\n' +
              self.color_monitor.background_ENDC)

        try:
            self.host = str(config['Server_conf']['server_host'])
            self.port = str(config['Server_conf']['server_port'])
            self.timeout = str(config['Server_conf']['timeout'])
            self.bytelimit = str(config['Server_conf']['bytelimit'])
            self.number_of_canal = str(config['Server_conf']['number_of_canal'])

            self.folder_SSL_conf = str(config['SSL_conf_SRV']['folder_SSL_conf'])
            self.ca_certs = str(config['SSL_conf_SRV']['ca_certs'])
            self.certfile = str(config['SSL_conf_SRV']['certfile'])
            self.keyfile = str(config['SSL_conf_SRV']['keyfile'])

            # Initiate socket
            self.socket = None
            self.securesocket = None


        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Missing of Misconfiguration in the config.ini file : {}\n'.format(
                    err),
                self.color_monitor.background_ENDC)

        print(
            self.color_monitor.background_OKGREEN + '[+] Server configured !\n\n Display of the configured options : \n'
            , '\n --Network and Common Configurations-- \n\n'
            , 'host : ' + self.host + '\n'
            , 'port : ' + self.port + '\n'
            , 'timeout : ' + self.timeout + '\n'
            , 'byte limit : ' + self.bytelimit + '\n'
            , 'number of canal : ' + self.number_of_canal + '\n'
            , '\n --SSL Configurations of Server-- \n\n'
            , 'CA_crt : ' + self.ca_certs + '\n'
            , 'SRV_crt : ' + self.certfile + '\n'
            , 'Keyfile : ' + self.keyfile + '\n')

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

        print(self.color_monitor.background_OKCYAN + '[*] Trying to secure the connexion ...\n' +
              self.color_monitor.background_ENDC)

        try:
            # Secure the connection with certificates

            # Wrap the connection through SSL
            self.securesocket = ssl.wrap_socket(connection,
                                                server_side=True,
                                                ca_certs=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                          self.folder_SSL_conf) + '/' + self.ca_certs),
                                                certfile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                          self.folder_SSL_conf) + '/' + self.certfile),
                                                keyfile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                         self.folder_SSL_conf) + '/' + self.keyfile),
                                                cert_reqs=ssl.CERT_REQUIRED,
                                                ssl_version=ssl.PROTOCOL_TLSv1_2)

            # Get the certificate from the client
            client_cert = self.securesocket.getpeercert()

            client_subject = dict(item[0] for item in client_cert['subject'])
            client_CommonName = client_subject['commonName']

            # Check if the client has or not a certificate
            if not client_cert:
                raise Exception("Unable to get the certificate from the client")

            # Check if Common Name issued respect the politic
            if client_CommonName != 'ClientApplication':
                raise Exception("Incorrect common name in client certificate")

            # Check the validity of the client certificate
            NotBefore = ssl.cert_time_to_seconds(client_cert['notBefore'])
            NotAfter = ssl.cert_time_to_seconds(client_cert['notAfter'])
            ActualTime = time.time()

            if ActualTime < NotBefore:
                raise Exception("Client certificate not yet active")

            if ActualTime > NotAfter:
                raise Exception("Expired client certificate")

            print(
                self.color_monitor.background_OKGREEN + '[+] Secure connection establish !!! \n' + self.color_monitor.background_ENDC)
            print(
                self.color_monitor.background_OKCYAN + '[*] Waiting message from client ... \n' + self.color_monitor.background_ENDC)

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Error in the initiation of the secure socket : {} \n'.format(
                    err),
                self.color_monitor.background_ENDC)
            quit()

        while True:
            # Received data stream limited to self.bytelimit rate)
            data = self.securesocket.recv(int(self.bytelimit)).decode()
            if not data:
                continue
            print(self.color_monitor.background_OKCYAN + '[*] From connected user : {} \n'.format(str(data)) +
                  self.color_monitor.background_ENDC)
            self.securesocket.close()
            self.socket.close()
            break


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    SocketServerTest = SocketServer()
    SocketServerTest.tunnel_com()
