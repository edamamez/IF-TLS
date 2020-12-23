import IFTLS
import dpkt
import time

def parse_pcap_and_send(i, tracename):
    '''
    The client parses a pcap file containing IoT traffic and sends it to the server

    Parameters:
        i: The IFTLS instance
        tracename: The name of the file to be parsed (.pcap extension)

    Returns:
        None
    '''

    # ---- Open PCAP file and reader object ---- #
    f = open(tracename, "rb")
    timestamps = []
    for ts, pkt in dpkt.pcap.Reader(f):
        # ---- Append timestamp to list ---- #
        timestamps.append(ts)

    # ---- Send out a message pertaining to each packet ---- #
    for j in range(len(timestamps) - 1):
        print("[INFO] Sent message: " + str(j))
        i.iftls_send(str(j))

        # ---- Receive echo from server and decrypt using if-tls session key ---- #
        i.iftls_receive()

        if timestamps[j+1] - timestamps[j] > 0:
            time.sleep(timestamps[j+1] - timestamps[j])

if __name__ == '__main__':
    i = IFTLS.IFTLS()

    i.initialize_client('localhost', 12349, 'localhost', 12348)

    # ---- Send data from PCAP file representing IoT traffic ---- #
    parse_pcap_and_send(i, "../data/single_session_25.pcap")

    # ---- Close connection ---- #
    i.iftls_close()
