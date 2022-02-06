import os
import sys
import qrcode

if len(sys.argv) < 2:
    secret_message = input("Please provide a secret message: ").encode('ASCII')
else:
    try:
        secret_message = sys.argv[1].encode('ASCII')
    except TypeError:
        print("Argument is not a string!")
        quit()

if len(sys.argv) == 3:
    outputFile = sys.argv[2]
else:
    outputFile = "qrcode.png"

# Make our qrcode
code = qrcode.make(secret_message)
code.save(outputFile)
