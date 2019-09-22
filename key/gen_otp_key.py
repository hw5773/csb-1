import random
import sys

OUTPUT_FILE = "otp-key.txt"
KEY_LENGTH = 128

def usage():
    print ("Random Key Generator: a key stream of 1K bytes is generated")
    print ("Usage: python3 gen_otp_key.py [output file]")
    print ("The default output file name is \"otp-key.txt\"")
    exit(1)

def main():
    if len(sys.argv) > 2 or len(sys.argv) < 1:
        usage()

    if len(sys.argv) == 2:
        ofname = sys.argv[1]
    else:
        ofname = OUTPUT_FILE

    keys = []
    for i in range(KEY_LENGTH):
        keys.append(random.randint(0, 255))

    keybytes = bytearray(keys)
    of = open(ofname, "wb")
    of.write(keybytes)

if __name__ == "__main__":
    main()
