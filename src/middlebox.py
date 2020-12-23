import IFTLS

if __name__ == '__main__':
    i = IFTLS.IFTLS()
    i.initialize_middlebox(12347)
    i.inspect_traffic()
