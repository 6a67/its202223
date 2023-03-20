#!/usr/bin/env python3.10
import argparse
import base64
import hashlib
import signal
import socket

# socket is global for signal handling
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def crack_password(host, port, username, word_dict):
    global s
    try:
        # connect to server
        s.connect((host, port))
    except:
        print("Connection failed")
        exit(1)

    # used for progress bar
    to_test = len(word_dict)
    tested = 0

    for password in word_dict:
        checked = False
        while not checked:
            # create sha3 hash of password
            h = hashlib.sha3_512()
            h.update(password.encode())
            h = h.digest()

            # encode h with base64
            h = base64.b64encode(h)

            send_msg = f"{username}:".encode() + h

            s.sendall(send_msg)
            data = s.recv(1024)

            msg = data.decode()
            # print(msg)

            if "false" in msg:
                # password is wrong and checked is set to true to continue with the next password
                checked = True
            elif "refused" in msg:
                # not so nice looking way to restart the socket
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                # checked is not set to true to retry the same password
                continue
            elif "correct" in msg:
                # password is correct
                s.close()
                return password, h
            else:
                print("\nUnexpected response from server")
                s.close()
                exit(1)

        tested += 1

        # progress bar
        progressed = round(tested / to_test, 4)

        routes = int(progressed * 40) * '#'
        dashes = (40 - int(progressed * 40)) * '-'
        print(
            f"\r{tested}/{to_test} [{routes}{dashes}] {progressed * 100:.2f}%", end="")

    return None, None


def load_wordlist(path, intensiveMode=False):
    word_dict = []
    obf_chars = {
        'a': '@',
        'A': '@',
        'c': '(',
        'C': '(',
        'e': '€',
        'E': '€',
        'i': '|',
        'I': '|',
        'h': '#',
        'H': '#',
        'n': '~',
        'N': '~',
        's': '$',
        'S': '$',
        't': '+',
        'T': '+',
        'v': '>',
        'V': '>',
        'y': '<',
        'Y': '<'
    }

    with open(path, "r") as f:
        data = f.read()
        # split data at whitespace
        word_dict = data.split()

    # convert word_dict to a set to remove duplicates
    word_dict = set(word_dict)

    if intensiveMode:
        # this seems a bit too much, regarding the task, but something else didn't work and while I tried fixing that, I made this which is why I kept it

        # convert all words to uppercase
        tmp = [w.upper() for w in word_dict]
        word_dict = word_dict.union(tmp)
        # convert all words to lowercase
        tmp = [w.lower() for w in word_dict]
        word_dict = word_dict.union(tmp)
        # convert all words to capitalized (first letter uppercase)
        tmp = [w.capitalize() for w in word_dict]
        word_dict = word_dict.union(tmp)

        # generate obfuscated words and add them to the word_dict
        old_len = len(word_dict)
        new_len = 0

        while old_len != new_len:
            print(
                f"\rGenerating password list... - {new_len} passwords generated", end="")

            old_len = new_len
            tmp_set = set()

            for word in word_dict:
                for k, v in obf_chars.items():
                    # find all occurrences of k in word and replace them one by one with v
                    index = word.find(k)
                    while index != -1:
                        tmp = word
                        tmp = tmp[:index] + v + tmp[index + 1:]
                        tmp_set.add(tmp)
                        index = word.find(k, index + 1)

            new_len = len(tmp_set)
            word_dict = word_dict.union(tmp_set)

    else:
        # replace every character in the word_dict with the obfuscated character and add it to the word_dict
        tmp_set = set()
        for word in word_dict:
            for k, v in obf_chars.items():
                word = word.replace(k, v)
            tmp_set.add(word)
        word_dict = word_dict.union(tmp_set)

    # task has a different ~ than my keyboard
    tmp = [w.replace("~", "∼") for w in word_dict]
    word_dict = word_dict.union(tmp)

    return word_dict

# signal handling for SIGINT


def signal_handler(sig, frame):
    global s
    s.close()
    print("\nConnection closed")
    exit(0)


# main
if __name__ == "__main__":

    # add signal handler for SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # ArgumentParser
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--username", help="Username to crack",
                        required=False, type=str, default="ITS202223")
    parser.add_argument("--host", help="Host to connect to",
                        required=False, type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Port to connect to",
                        required=False, type=int, default=5000)
    parser.add_argument("--intensive", help="Use intensive wordlist generation. Takes a lot of extra time",
                        required=False, action='store_true')
    # argument without prefix is the wordlist path
    parser.add_argument("wordlist", help="Path to wordlist", type=str)

    args = parser.parse_args()

    word_dict = set()
    try:
        word_dict = load_wordlist(args.wordlist, args.intensive)
    except:
        print("\nError loading wordlist")
        exit(1)

    password = None
    try:
        password, hash = crack_password(
            args.host, args.port, args.username, word_dict)
    except:
        print("\nSomething went wrong while cracking the password")
        exit(1)

    if password:
        print(f"\r{password}: {args.username}:SHA{hash.decode()}")
    else:
        print("\rNo password found" + " " * 50)
        exit(1)
