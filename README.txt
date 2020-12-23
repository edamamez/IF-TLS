Inspection-Friendly TLS (IF-TLS) was created for fulfillment of a Major Qualifying Project (MQP) at Worcester Polytechnic Institute.

IF-TLS is a TLS-based protocol that preserves the encryption offered by TLS while allowing middleboxes to observe traffic. We delegate control to the user to decide which devices should be inspected and what middleboxes have decryption capabilities through an access control list (ACL). The IF-TLS manager uses the ACL to obtain and share devices’ session keys with trusted middleboxes. Additionally, middleboxes involved can be located anywhere in the network, including the cloud and the local area network.

The main library and modules that implement IF-TLS are found in the src folder. The data file contains the keys and certificates used for asymmetric cryptography and authentication. We intentionally leave these in the repo for ease of use -- they were generated using `rsa` and `openssl` and are NOT actively used outside of local testing. If you plan to use IF-TLS with any meaningful data, you should create new keys and certificates.

To run out-of-the-box (defaulted to be all on localhost, no middlebox):
  - Ensure you are using Python 3 or download if not
  - Install all dependencies: $ pip3 install -r requirements.txt
  - Run the following (in the listed order) in separate terminals:
      - $ python3 manager.py
      - $ python3 server.py
      - $ python3 client.py

Configuration Steps (for using tinycore VMs):
  - Follow instructions to set up tinycore (including installing python3, running the setup script, and configuring the HQ VM as a DHCP server)
  - Make unique eth1 IP addresses for each VM in /opt/eth1.sh
  - Set up the following static routes:
    - On the client: $ sudo route add default gw {Manager_eth1_IP} eth1
    - On the HQ: $ sudo route add default gw {MB_eth1_IP} eth1

How to run tests with a middlebox:
  - Run the following (in the listed order) in separate terminals:
    $ python3 manager.py
    $ sudo -E python3 middlebox.py    * This is so scapy can sniff packets
    $ python3 server.py
    $ python3 client.py


Authors: Eda Zhou and Joseph Turcotte
