import binascii
import sys
import re

def main():
    if len(sys.argv) != 2:
        print("Usage: python raw2hex.py <input_file>")
        sys.exit(0)

    print("Reading file:", sys.argv[1])
    try:
        data = binascii.b2a_hex(open(sys.argv[1], "rb").read()).decode('utf-8')
    except:
        print("Error: Could not read file.")
        sys.exit(0)
    
    print("Converted output:")
    
    if "-list" in sys.argv:
        print("0x" + ",0x".join(re.findall('..', data)))
    else:
        print("\\x" + "\\x".join(re.findall('..', data)))

main()