# Note that IP routes need to be added on the hosts in order for this to run as intended
# These instructions can be found in the README

import socket, ssl
import scrypt, secrets, dpkt
import os, sys, time, random, string, csv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import Poly1305
from base64 import b64decode,b64encode
from scapy.all import *

class IFTLS:

    #  NOTE that the code will have to be updated to remain compatible if any of these are changed!!
    asym_cipher="PKCS1_OAEP" # The cipher used for the asymmetric encryption
    iftls_cipher="AES" # The cipher used for the symmetric encryption
    mac_cipher="Poly1305" # The cipher used for MAC encryption
    len_pre_master=128 # The length of the pre-master secret (number of bytes), length of each component (session passphrase, session salt, mac passphrase, mac salt) is equal

    def __init__(self, socket=None, session_key="", mac_key="", end_string="---END---"):
        '''
        IFTLS constructor

        Parameters:
            socket : The socket object (used between client and server)
            session_key (string): The session key used for the IFTLS session, this will be set automatically when client/server initialize is called
            mac_key (string): The MAC key used for the IFTLS session, this will be set automatically when client/server initialize is called
            end_string (string): The string that marks the end of a packet, will default to "---END---"

        '''
        self.socket = socket
        self.session_key = session_key
        self.mac_key = mac_key
        self.end_string = end_string

    def initialize_client(self, server_name, serv_port, manager_name, manager_port, verbose=False):
        '''
        Client functionality for IF-TLS
        Initializes client-server and client-manager

        Parameters:
            server_name (string): The name (or IP) of the server to connect to
            serv_port (int): The port number to use for connecting to the server
            manager_name (string): The name (or IP) of the manager to connect to
            manager_port (int): The port number to use for connecting to the manager
            verbose (boolean): Default to False (off), specify True if you want performance to be logged to a text file

        Returns:
            None

        '''

        if verbose:
            output = open("client_log.txt", "a+")
            conn_serv_time = time.time()

        # ---- Execute TCP handshake with server ---- #
        self.socket = self.__sock_client_side__(server_name, serv_port)

        # ---- Establish IF-TLS with Server ---- #
        if self.socket != None:

            # ---- Send hello with ciphers (session and mac), length of pre-master to server ---- #
            packet = 'Cipher=' + self.iftls_cipher + ' Mac=' + self.mac_cipher + ' Premaster_length=' + str(self.len_pre_master) + self.end_string
            self.socket.sendall(packet.encode())

            # ---- Receive server's hello: public key, certificate, and cipher ---- #
            serv_hello = self.__recv_data__()
            print("Received public key and cerificate from server")
            serv_cert = serv_hello[serv_hello.find('-----BEGIN CERTIFICATE-----')+len('-----BEGIN CERTIFICATE-----'):serv_hello.find('-----END CERTIFICATE-----')]
            serv_string_key = serv_hello[serv_hello.find('-----BEGIN PUBLIC KEY-----')+len('-----BEGIN PUBLIC KEY-----'):serv_hello.find('-----END PUBLIC KEY-----')]
            serv_public_key = RSA.importKey(b64decode(serv_string_key))
            # ---- Check ciphers are the ones expected ---- #
            serv_cipher = serv_hello[serv_hello.find('Cipher=') + len('Cipher='):]
            if serv_cipher != self.asym_cipher:
                print("Cipher not accepted, closing connection")
                self.socket.close()
                return

            # ---- Send pre-master secret to server using server's public key ---- #
            # secrets uses os.urandom() which is a cryptographically secure way to generate random bytes according to the OS
            pre_master = secrets.token_hex(64)  # (1 byte = 2 hexadecimal digits --> 128 characters) The first 32 chars are for the session key, the next 32 are for the session key salt, the next 32 are for the MAC key, the final 32 are for the MAC key salt
            cipher = PKCS1_OAEP.new(serv_public_key)
            cipher_text = cipher.encrypt(pre_master.encode())
            self.socket.sendall(cipher_text)

            # ---- Compute pre-master secret into session key and MAC key using passphrase and salt---- #
            len_component = int(self.len_pre_master/4) # length of each component (session passphrase, session salt, mac passphrase, mac salt) is equal
            self.session_key = scrypt.hash(pre_master[:len_component], pre_master[len_component:2*len_component], buflen=32)
            self.mac_key = scrypt.hash(pre_master[2*len_component:3*len_component], pre_master[3*len_component:], buflen=32)

            # ---- Receive ack from server and decrypt + verify using if-tls session key + mac key---- #
            ack_packet = self.__recv_data__()
            decrypted_msg = self.__decrypt_and_verify__(ack_packet)

            # ---- Check ack from server ---- #
            if decrypted_msg == 'ack':
                if verbose:
                    ack_serv_time = time.time()
                    output.write("Client-Server initialization time: " + str(ack_serv_time - conn_serv_time) + '\n')
                print('Ack received from server; session key established: ', self.session_key, "\nMAC key established: ", self.mac_key)
            else:
                print('Expected ack, exiting')
                return

        # ---- Establish TLS with manager ---- #
        if verbose:
            conn_manager_time = time.time()
        s_manager, secure_sock_manager = self.__secure_sock_client_side__(manager_name, manager_port, "client", "manager")

        if s_manager != None and secure_sock_manager != None:

            # ---- Send pre-computed session key and salt (first 64 chars of the pre_master) and cipher to the manager ---- #
            manager_pre_master = pre_master[:2*len_component] + ' Cipher=' + self.iftls_cipher
            self.__encrypt_and_send__(manager_pre_master, secure_sock_manager, "manager")

            # ---- Wait for acknowledgement message from manager ---- #
            ack = self.__tls_recv_and_decrypt__(secure_sock_manager, "client")
            if ack == 'ack':
                if verbose:
                    ack_manager_time = time.time()
                    output.write("Client-Manager initialization time: " + str(ack_manager_time - conn_manager_time) + '\n')
                print('Ack received from manager: ready to start sending data...\n')
            elif ack == 'nack':
                print('Cipher was not accepted by a middlebox, ending IF-TLS\n')
                s_manager.close()
                secure_sock_manager.close()
                self.socket.close()
                return
            else:
                print('Ack not received properly from manager... ending IF-TLS\n')
                s_manager.close()
                secure_sock_manager.close()
                self.socket.close()
                return

            # ---- Close sockets ---- #
            s_manager.close()
            secure_sock_manager.close()
        return

    def initialize_server(self, port_num):
        '''
        Server functionality for IF-TLS

        Parameters:
            port_num (int): The port number to use for connecting to the server

        Returns:
            None

        '''

        # ---- Create a public-private key pair if it does not already exist ---- #
        if not os.path.isfile(self.__get_data_path__("server_public_key.pem")):
            self.__generate_encryption_key_pair__("server")

        # ---- Bind/listen for client TCP connection ---- #
        s = self.__sock_server_side__(port_num)
        self.socket, addr = s.accept()
        print("Got connection from {0}".format(addr))

        # ---- Establish TLS with Client ---- #

        # ---- Receive client hello with ciphers (session and mac), length of pre-master ---- #
        cli_hello = self.__recv_data__()

        # ---- Check ciphers and length are the ones expected ---- #
        iftls_cipher = cli_hello[len('Cipher='):cli_hello.find(' Mac=')]
        mac_cipher = cli_hello[cli_hello.find('Mac=') + len('Mac='):cli_hello.find(' Premaster_length=')]
        len_pre_master = int(cli_hello[cli_hello.find('Premaster_length=') + len('Premaster_length='):])
        if iftls_cipher != self.iftls_cipher or mac_cipher != self.mac_cipher or len_pre_master != self.len_pre_master:
            print("Ciphers or length not accepted, closing connection")
            c.close()
            return

        # ---- Send public key, certificate, and asymmetric cipher to client (server hello) ---- #
        certificate = open(self.__get_data_path__("server_certificate.pem"), "rb")
        public_key = open(self.__get_data_path__("server_public_key.pem"), "rb")
        packet = certificate.read() + public_key.read() + ("Cipher=" + self.asym_cipher + self.end_string).encode()
        self.socket.sendall(packet)
        certificate.close()
        public_key.close()

        # ---- Receive pre-master secret from client ---- #
        enc_pre_master = self.socket.recv(256)

        # ---- Decrypt pre-master from client (asymmetric)---- #
        private_key = RSA.importKey(open(self.__get_data_path__("server_private_key.pem"), "r").read())
        decode_cipher = PKCS1_OAEP.new(private_key)
        pre_master = decode_cipher.decrypt(enc_pre_master)

        # ---- Compute pre-master secret ---- #
        len_component = int(self.len_pre_master/4) # length of each component (session passphrase, session salt, mac passphrase, mac salt) is equal
        self.session_key = scrypt.hash(pre_master[:len_component], pre_master[len_component:2*len_component], buflen=32)
        self.mac_key = scrypt.hash(pre_master[2*len_component:3*len_component], pre_master[3*len_component:], buflen=32)
        print("Computed session key: ", self.session_key, "\nMAC key: ", self.mac_key)

        # ---- Send ack to client using TLS session key and MAC ---- #
        self.iftls_send('ack')

        return

    def initialize_manager(self, path_to_acl, cli_port, mb_port, device_name, verbose=False):
        '''
        Manager functionality for IF-TLS

        Parameters:
            path_to_acl (string): The path to the CSV file that contains the access control list data
            cli_port (int): The port number to connect to the client
            mb_port (int): The port number to establish a connection with each middlebox
            device_name (string): The name of the client device
            verbose (boolean): Default to False (off), specify True if you want performance to be logged to a text file

        Returns:
            None

        '''

        # ---- Create acl from supplied file ---- #
        path = self.__get_data_path__(path_to_acl)
        acl = self.__create_acl__(path)

        # ---- Establish secure socket with client ---- #
        s, secure_sock = self.__secure_sock_server_side__(cli_port, "client", "manager")

        if s != None and secure_sock != None:
            # ---- Receive pre_master from client ---- #
            pre_master = self.__tls_recv_and_decrypt__(secure_sock, "manager")
            print("Received pre_master")

            if verbose:
                output = open("manager_log.txt", "a+")
                output.write("+++++ MANAGER NEW ROUND +++++\n")
                start_time = time.time()

        # ---- Read acl to determine which middleboxes have decryption capabilities ---- #
        middleboxes = acl[device_name]
        ack_msg = 'ack'
        for mb in middleboxes:
            # ---- Establish TLS connection with middlebox ---- #
            s_mb, secure_sock_mb = self.__secure_sock_client_side__(mb, mb_port, "manager", "middlebox")

            if s_mb != None and secure_sock_mb != None:
                # TODO Send device ID to the middlebox
                # ---- Send client's pre_master to MB ---- #
                self.__encrypt_and_send__(pre_master, secure_sock_mb, "middlebox")

                # ---- Wait for acknowledgment from middlebox ---- #
                ack_msg = self.__tls_recv_and_decrypt__(secure_sock_mb, "manager")
                if ack_msg == 'ack':
                    print('Ack received from middlebox\n')
                elif ack_msg == 'nack':
                    print('Cipher not accepted by middlebox, sending nack\n')
                    secure_sock_mb.close()
                    s_mb.close()
                    break
                else:
                    print('Ack message not received properly from middlebox...\n')
                    secure_sock_mb.close()
                    s_mb.close()
                    break

                # ---- Close sockets ---- #
                secure_sock_mb.close()
                s_mb.close()

        # ---- Send ack message to client ---- #
        self.__encrypt_and_send__(ack_msg, secure_sock, "client")

        if verbose:
            fin_time = time.time()
            output.write("Manager-Middlebox initialization time: " + str(fin_time - start_time) + '\n')

        # ---- Close sockets ---- #
        secure_sock.close()
        s.close()

        return

    def initialize_middlebox(self, manager_port):
        '''
        Middlebox functionality for IF-TLS

        Parameters:
            manager_port (int): The port number used to connect to the manager

        Returns:
            None

        '''

        # ----- Establish TLS with manager ---- #
        s, secure_sock = self.__secure_sock_server_side__(manager_port, "manager", "middlebox")

        if s != None and secure_sock != None:
            # ---- Receive pre_master from manager, check cipher, and compute session key ---- #
            pre_master = self.__tls_recv_and_decrypt__(secure_sock, "middlebox")
            cipher_index = pre_master.find(' Cipher=')
            cli_cipher = pre_master[cipher_index + len(' Cipher='):]
            if cli_cipher != self.iftls_cipher:
                # Return nack to manager if not accepted cipher
                print("Cipher not compatible, sending nack and closing connection")
                self.__encrypt_and_send__('nack', secure_sock, "manager")
                secure_sock.close()
                s.close()
                return

            self.session_key = scrypt.hash(pre_master[:int(cipher_index/2)], pre_master[int(cipher_index/2):cipher_index], buflen=32) # Assumes passphrase and salt are even lengths
            print("Received and calculated session key: ", self.session_key)
            # ---- Send acknowledgement to manager ---- #
            self.__encrypt_and_send__('ack', secure_sock, "manager")

        # ---- Close sockets ---- #
        secure_sock.close()
        s.close()

        return

    def iftls_send(self, message):
        '''
        The client encrypts a message using the session (symmetric) key

        Parameters:
            message (string): The data to be transmitted through the network

        Returns:
            None

        '''

        session_cipher = AES.new(key=self.session_key, mode=AES.MODE_CTR)
        payload = session_cipher.encrypt(message.encode())
        nonce = session_cipher.nonce
        mac = Poly1305.new(key=self.mac_key, cipher=AES, data=message.encode())
        packet = 'Payload:' + b64encode(payload).decode() + 'MAC:' + mac.hexdigest() + 'Nonce:' + b64encode(nonce).decode() + 'MAC nonce:' + b64encode(mac.nonce).decode() + self.end_string
        self.socket.sendall(packet.encode())

    def iftls_receive(self):
        '''
        Receives a message over the socket, verifies the packet,
        and returns the decrypted message.

        Parameters:
            None

        Returns:
            message (string): The decrypted payload

        '''
        packet = self.__recv_data__()
        return self.__decrypt_and_verify__(packet)

    def iftls_close(self):
        '''
        Sends the end connection ('close') message and closes socket

        Parameters:
            None

        Returns:
            None

        '''
        print("Sending closing message")
        self.iftls_send("Close Connection")

        self.socket.close()
        return

    def inspect_traffic(self):
        '''
        Inspects the packets collected by scapy (this is the callback function) and decrypts them if they are part of if-tls

        Parameters:
            session_key: The symmetric key used encrypt the packet

        Returns:
            None

        '''
        packet = sniff(prn=self.__inspect_pkt__, store=0, iface='eth1')

    ## ---------- PRIVATE Functions ---------- ##

    def __create_acl__(self, top_secret_file):
        '''
        An access control list is created from a csv file containing middlebox decryption capabilities for each smart device

        Parameters:
            top_secret_file (string): The path to the file that contains the access control list data (device IDs followed by a sorted order of middleboxes)

        Returns:
            dictionary: Keys are strings representing the smart device MAC addresses, values are sorted lists of middlebox IP addresses that have decryption capabilities

        Example: acl = {'00:03:D4:E5:2F:16': ['10.0.0.1', '10.0.0.2'], ...}

        '''
        acl = {}

        # Open top secret file
        f = open(top_secret_file, "r")

        # Read file line by line and accumulate values as lists in the acl structure
        for line in f:
            line = line.strip('\n')
            values = line.split(",")
            device_id = values[0]
            middlebox_IPs = []
            for i in range(1, len(values)):
                middlebox_IPs.append(values[i])

            # Register key-value pair in dictionary
            acl[device_id] = middlebox_IPs

        f.close()
        return acl

    def __get_data_path__(self, file_name):
        '''
        Compute the file path for depending on operating system (Windows, Linux/MacOS). Assumes that the file is in a '../data/' folder.

        Parameters:
            file_name (string) - The name of the file

        Returns:
            path (string) - an absolute path to the file

        '''
        my_path = os.path.abspath(os.path.dirname(__file__))

        if os.name == 'nt': # if Windows operating system
            return os.path.join(my_path, "..\\data\\", file_name)
        else:
            return os.path.join(my_path, "../data", file_name)

    def __generate_encryption_key_pair__(self, entity_name):
        '''
        An RSA public-private key pair is generated and written to disk (path: ../data/'name') for encryption and decryption of messages.

        Parameters:
            entity_name (string) - "client" or "server", indicates which entity we are generating keys for

        Returns:
            None

        '''

        # Create and write private key to disk
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_file_name = entity_name + "_private_key.pem"
        private_file_path = self.__get_data_path__(private_file_name)
        with open(private_file_path, 'wb') as f:
            f.write(pem)

        # Create and write public key to disk
        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_file_name = entity_name + "_public_key.pem"
        public_file_path = self.__get_data_path__(public_file_name)
        with open(public_file_path, 'wb') as f:
            f.write(pem)

    def __encrypt_and_send__(self, message, secure_sock, endpoint_name):
        '''
        The client encrypts a message using the endpoint's key and sends it over the network

        Parameters:
            message (string): The data to be transmitted through the network
            secure_sock: The socket object used to send the data through the network
            endpoint_name (string): The entity name of the endpoint (e.g. "client", "manager", "middlebox", or "server")

        Returns:
            None

        '''

        # ---- Create a public-private key pair if it does not already exist ---- #
        if not os.path.isfile(self.__get_data_path__(endpoint_name + "_public_key.pem")):
            self.__generate_encryption_key_pair__(endpoint_name)

        # Open endpoint's public key file
        with open(self.__get_data_path__(endpoint_name + "_public_key.pem"), "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        message = message.encode()

        # Encrypt data with endpoint's public key
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Write the encrypted message to the secure socket
        secure_sock.write(encrypted)

    def __decrypt_and_verify__(self, packet):
        '''
        Given the data from a packet, checks the MAC (will print error and return empty if it is improper) and returns the decrypted string.

        Parameters:
            packet (string): The full packet, formatted as "Payload:____MAC:____Nonce:____MAC nonce:____"

        Returns:
            message (string): The decrypted payload

        '''
        payload, mac, nonce, mac_nonce = self.__split_packet__(packet)
        decrypted_msg = self.__decrypt_sym__(payload, nonce)

        # ---- Check echo message from server (MAC and message) ---- #
        if self.__check_MAC__(decrypted_msg, mac, mac_nonce):
            return decrypted_msg.decode()
        else:
            print("** Improper message received (MAC not verified) **")
            return

    def __tls_recv_and_decrypt__(self, secure_sock, endpoint_name):
        '''
        The server decrypts a message using the endpoint's key and returns it

        Parameters:
            secure_sock: The socket object used to receive data through the network
            endpoint_name (string): The entity receiving the message (e.g. "client", "manager", "middlebox", or "server")

        Returns:
            decrypted (string): The plaintext message

        '''

        # Receive message through the secure socket
        encrypted = secure_sock.recv(2048)

        # Open receiving endpoint's private key
        with open(self.__get_data_path__(endpoint_name + "_private_key.pem"), "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Decrypt the message using the receiving endpoint's private key
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decode the message
        decrypted = decrypted.decode()

        return decrypted

    def __recv_data__(self):
        '''
        Receives a message over the socket until the end_string is found, returns payload as a string and strips the end_string.

        Parameters:
            None

        Returns:
            data (string): The data received

        '''

        packet = ''
        while True:
            data = self.socket.recv(1024)
            packet += data.decode()
            if not data or self.end_string in packet:
                break

        return packet[:len(packet)-len(self.end_string)]

    def __split_packet__(self, packet):
        '''
        Takes a packet and returns the parsed contents as bytestrings.
        The packet must be formatted as "Payload:____MAC:____Nonce:____MAC nonce:____".

        Parameters:
            packet (string): The full string packet

        Returns:
            payload (bytestring), mac (bytestring), nonce (bytestring), mac_nonce (bytestring): The separate contents

        '''

        payload = b64decode(packet[packet.find('Payload:')+len('Payload:'):packet.find('MAC:')].encode())
        mac = packet[packet.find('MAC:')+len('MAC:'):packet.find('Nonce:')]
        nonce = b64decode(packet[packet.find('Nonce:')+len('Nonce:'):packet.find('MAC nonce:')].encode())
        mac_nonce = b64decode(packet[packet.find('MAC nonce:')+len('MAC nonce:'):].encode())

        return payload, mac, nonce, mac_nonce

    def __decrypt_sym__(self, payload, nonce):
        '''
        Takes an encrypted payload and the nonce used and returns the decrypted payload.

        Parameters:
            payload (bytestring): The encrypted bytestring payload
            nonce (bytestring): The nonce used to encrypt the payload


        Returns:
            message (bytestring): The decrypted payload

        '''

        session_cipher = AES.new(key=self.session_key, mode=AES.MODE_CTR, nonce=nonce)
        message = session_cipher.decrypt(payload)
        return message

    def __check_MAC__(self, message, mac, mac_nonce):
        '''
        Takes an decrypted message, the MAC, the MAC key, and the MAC nonce used and returns if the MAC matches the message.

        Parameters:
            message (bytestring): The decrypted message
            mac (string): The MAC
            mac_nonce (bytestring): The nonce used to encrypt the MAC


        Returns:
            Error code (int): 1 on success, 0 on failure
        '''
        mac_verify = Poly1305.new(data=message, key=self.mac_key, nonce=mac_nonce, cipher=AES)
        try:
            mac_verify.hexverify(mac)
            print('Message verified')
            return 1
        except:
            print('Message could not be verified')
            return 0

    def __sock_client_side__(self, server_name, port_num):
        '''
        Abstraction for any client to initiate a connection with a server

        Parameters:
            server_name (string): The name of the server to connect to
            port_num (number): The port number to establish the connection

        Returns:
            s: Socket object that was created (or None if one could not be created)

        '''

        # ---- Try to resolve host name ---- #
        try:
            host_ip = socket.gethostbyname(server_name)
        except socket.gaierror:
            print("Error resolving host")
            return None

        # ---- Create a socket and connect ---- #
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Socket successfully created")
            s.setblocking(1);
            s.connect((host_ip, port_num))
        except socket.error as err:
            print("Socket creation failed with error {0}".format(err))
            return None

        return s

    def __secure_sock_client_side__(self, server_name, port_num, client_entity_name, server_entity_name):
        '''
        Abstraction for any client to initiate a secure connection with a server

        Parameters:
            server_name (string): The name of the server to connect to
            port_num (number): The port number to establish the connection
            client_entity_name (string): The entity name of the client (e.g. "client", "manager", or "middlebox")
            server_entity_name (string): The entity name of the server (e.g. "manager", "middlebox", or "server")

        Returns:
            s, secure_sock: Socket objects that were created (or None if one or both could not be created)

        '''

        # ---- Create regular socket ---- #
        s = self.__sock_client_side__(server_name, port_num)

        # ---- Create SSL wrapper for secure socket ---- #
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.__get_data_path__(server_entity_name + "_certificate.pem"))
        context.load_cert_chain(certfile=self.__get_data_path__(client_entity_name + "_certificate.pem"), keyfile=self.__get_data_path__(client_entity_name + "_auth.key"))

        if ssl.HAS_SNI:
            secure_sock = context.wrap_socket(s, server_side=False, server_hostname=server_name)
        else:
            secure_sock = context.wrap_socket(s, server_side=False)

        # ---- Verify server ---- #
        cert = secure_sock.getpeercert()
        if not cert:
            print("ERROR: {0} could not be verified".format(server_name))
            return s, None

        print("The secure socket has successfully connected to host {0} with port number == {1}".format(server_name, port_num))

        return s, secure_sock

    def __sock_server_side__(self, port_num):
        '''
        Abstraction for any server to initiate a connection with a client

        Parameters:
            port_num (number): The port number to establish the connection

        Returns:
            s: Socket object that was created (or None if one could not be created)

        '''

        # ---- Bind/listen for client connection ---- #
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind( ('', port_num) )
            s.listen(5)
            print("Socket successfully created; listening on port {0}".format(port_num))
        except socket.error as err:
            print("Socket creation failed with error {0}".format(err))
            return None

        return s

    def __secure_sock_server_side__(self, port_num, client_entity_name, server_entity_name):
        '''
        Abstraction for any server to initiate a secure connection with a client

        Parameters:
            port_num (number): The port number to establish the connection
            client_entity_name (string): The entity name of the client (e.g. "client", "manager", or "middlebox")
            server_entity_name (string): The entity name of the server (e.g. "manager", "middlebox", or "server")

        Returns:
            s, secure_sock: Socket objects that were created (or None if one or both could not be created)

        '''

        # ---- Create regular socket ---- #
        s = self.__sock_server_side__(port_num)

        # ---- Establish secure socket with client ---- #
        secure_sock = None
        c, addr = s.accept()
        print("Got connection from {0}".format(addr))
        try:
            secure_sock = ssl.wrap_socket(c, server_side=True,ca_certs=self.__get_data_path__(client_entity_name + "_certificate.pem"),
                certfile=self.__get_data_path__(server_entity_name + "_certificate.pem"), keyfile=self.__get_data_path__(server_entity_name + "_auth.key"),
                cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLS)

            # ---- Verify client ---- #
            cert = secure_sock.getpeercert()
            if not cert:
                print("ERROR: Host {0} could not be verified".format(addr))
                return s, None

        except ssl.SSLError as e:
            print(e)

        print("The secure socket has successfully connected to host {0} with port number == {1}".format(addr, port_num))
        return s, secure_sock

    def __inspect_pkt__(self, packet):
        '''
        This is the callback function for scapy
        '''
        # ---- Check if packet is part of if-tls ---- #
        if Raw in packet:
            data = packet[Raw].load
            if b'Payload' in data:
                data = data.decode()
                data = data[:data.find(self.end_string)] # Strip end of file
                payload, mac, nonce, mac_nonce = self.__split_packet__(data)
                # ---- Decrypt message and print ---- #
                decrypted_msg = self.__decrypt_sym__(payload, nonce)
                print('Inspected message: ' + decrypted_msg.decode())
