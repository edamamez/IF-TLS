import IFTLS

if __name__ == '__main__':
    i = IFTLS.IFTLS()
    i.initialize_server(12349)

    # ---- Receive data from client and decrypt, echo message ---- #
    while True:
        decrypted_msg = i.iftls_receive()
        if not decrypted_msg:
            break
        if decrypted_msg == "Close Connection":
            print("Closing connection with client...")
            break

        print("[INFO] Received message: " + decrypted_msg)
        i.iftls_send(decrypted_msg)
