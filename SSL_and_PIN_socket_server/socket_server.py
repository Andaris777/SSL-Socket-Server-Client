import socket
import time
import ssl
import configparser
import os
import warnings

from Extra_features_script import *
from login_monitor import *

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
            self.byte_limit = str(config['Server_conf']['byte_limit'])
            self.number_of_canal = str(config['Server_conf']['number_of_canal'])

            self.folder_SSL_conf = str(config['SSL_conf_SRV']['folder_SSL_conf'])
            self.ca_certs = str(config['SSL_conf_SRV']['ca_certs'])
            self.cert_file = str(config['SSL_conf_SRV']['cert_file'])
            self.keyfile = str(config['SSL_conf_SRV']['keyfile'])

            # Initiate socket
            self.socket = None
            self.secure_socket = None

            # Initiate login monitor
            self.login_monitor = LoginMonitor()

            # Initiate flags
            self.flags_broken_pipe = 2
            self.flag_auth_get_elements = 2
            self.flag_auth_success = None

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
            , 'byte limit : ' + self.byte_limit + '\n'
            , 'number of canal : ' + self.number_of_canal + '\n'
            , '\n --SSL Configurations of Server-- \n\n'
            , 'CA_crt : ' + self.ca_certs + '\n'
            , 'SRV_crt : ' + self.cert_file + '\n'
            , 'Keyfile : ' + self.keyfile + '\n')

    def tunnel_com(self):
        """
        Method used to initiate the socket communication from the server
        :return: None
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

        # pdb.set_trace()
        try:
            # Secure the connection with certificates

            # Wrap the connection through SSL
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            context.load_cert_chain(certfile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                              self.folder_SSL_conf) + '/' + self.cert_file),
                                    keyfile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                             self.folder_SSL_conf) + '/' + self.keyfile))
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                  self.folder_SSL_conf) + '/' + self.ca_certs))

            self.secure_socket = context.wrap_socket(connection, server_side=True)
            self.secure_socket.settimeout(int(self.timeout))

            '''
            # Deprecated
            self.secure_socket = ssl.wrap_socket(connection,
                                                server_side=True,
                                                ca_certs=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                          self.folder_SSL_conf) + '/' + self.ca_certs),
                                                cert_file=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                          self.folder_SSL_conf) + '/' + self.certfile),
                                                keyfile=str(os.path.join((os.path.dirname(os.path.abspath(__name__))),
                                                                         self.folder_SSL_conf) + '/' + self.keyfile),
                                                cert_reqs=ssl.CERT_REQUIRED,
                                                ssl_version=ssl.PROTOCOL_TLSv1_2)
            '''

            # Get the certificate from the client
            client_cert = self.secure_socket.getpeercert()

            # Check if the client has or not a certificate
            if not client_cert:
                raise Exception("Unable to get the certificate from the client")

            client_subject = dict(item[0] for item in client_cert['subject'])
            client_common_name = client_subject['commonName']

            # Check if Common Name issued respect the politic
            if client_common_name != 'ClientApplication':
                raise Exception("Incorrect common name in client certificate")

            # Check the validity of the client certificate
            not_before = ssl.cert_time_to_seconds(client_cert['notBefore'])
            not_after = ssl.cert_time_to_seconds(client_cert['notAfter'])
            actual_time = time.time()

            if actual_time < not_before:
                raise Exception("Client certificate not yet active")

            if actual_time > not_after:
                raise Exception("Expired client certificate deprecated")

            print(
                self.color_monitor.background_OKGREEN + '[+] Secure connection establish !!! \n' + self.color_monitor.background_ENDC)
            print(
                self.color_monitor.background_OKCYAN + '[*] Waiting login/password from client ... \n' + self.color_monitor.background_ENDC)

        except Exception as err:
            print(
                self.color_monitor.background_FAIL + '[x] Error in the initiation of the secure socket : {} \n'.format(
                    err),
                self.color_monitor.background_ENDC)

            # Shutdown the connexion
            connection.close()
            self.socket.close()

            quit()

        while True:
            # Received data stream limited to self.byte_limit rate
            data = self.secure_socket.recv(int(self.byte_limit)).decode()
            if not data:
                continue
            # Verify secure connection established
            if self.flags_broken_pipe != 0:
                self.flags_broken_pipe = self.flags_broken_pipe - 1
                continue
            # Check login username/password
            # Retrieve username
            if self.flag_auth_get_elements != 0 and self.flag_auth_get_elements == 2:
                username = data
                self.flag_auth_get_elements = self.flag_auth_get_elements - 1
                continue
            # Retrieve password
            if self.flag_auth_get_elements != 0 and self.flag_auth_get_elements == 1:
                password = data
                self.flag_auth_get_elements = self.flag_auth_get_elements - 1
                # Check if the provided credentials are rights
                try:
                    success_or_not_in_authentification = self.login_monitor.login(username_to_log_with=username, password_to_log_with=password)

                    if success_or_not_in_authentification == 0 :
                        print(self.color_monitor.background_OKGREEN +
                              '[+] User {} is connected !!!\n'.format(username)
                              + self.color_monitor.background_ENDC)

                        # Re-initiate the flag of broken pipe (the client is going to check if the pipe is still open)
                        self.flags_broken_pipe = 2

                        print(
                            self.color_monitor.background_OKGREEN + '[+] Waiting message from {} ...\n'.format(username) + self.color_monitor.background_ENDC)
                        continue

                    else:
                        raise Exception(str(success_or_not_in_authentification))

                except Exception as err:
                    print(
                        self.color_monitor.background_FAIL + '[x] Connection failed : {}\n'.format(
                            err),
                        self.color_monitor.background_ENDC)
                    break

            print(self.color_monitor.background_OKCYAN + '[*] From user {} : {} \n'.format(username, str(data)) +
                  self.color_monitor.background_ENDC)

            self.flags_broken_pipe = 2
            self.secure_socket.close()
            self.socket.close()
            connection.close()
            break


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    SocketServerTest = SocketServer()
    SocketServerTest.tunnel_com()
