#!/usr/bin/env python3

from threading import Thread
from queue import Queue
from time import sleep

from sniffer import sniff
from sniffer import dissect
from detector import detect

def foreverify(f):
    
    def new_func(*args):
        while True:
            f(*args)
    
    return new_func

def main():
    
    # Using queues for synchronization and data control
    data_queue = Queue()
    channel = Queue()
    table = {}
    channel.put(table)
    
    print("Port scanner detector initialized")
    print("press [Ctrl+C] to quit")
    sniffer = Thread(target = foreverify(sniff), args = (data_queue,)) 
    dissector = Thread(target = foreverify(dissect), args = (data_queue, channel))
    detector = Thread(target = foreverify(detect), args = (channel,))
     
    sniffer.daemon = True
    dissector.daemon = True
    detector.daemon = True
    
    sniffer.start()
    dissector.start()
    detector.start()

    try:
        # Proof of concept showing we can fetch items from the queue
        # Note: later we may as well replace this with a call to one of the other functions
        num = 0
        while True:
            table = channel.get()
            size = len(table)
            if size != num:
                more_or_less = "more" if size > num else "less"
                print("we now have %d %s entries (total = %d)" % (size - num, more_or_less, size))
                num = size
            channel.put(table)
        
    except KeyboardInterrupt:
        print()

if __name__ == "__main__": 
    main()

