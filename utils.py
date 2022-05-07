colors = {
    "Black": "\u001b[30m",
    "Red": "\u001b[31m",
    "Green": "\u001b[32m",
    "Yellow": "\u001b[33m",
    "Blue": "\u001b[34m",
    "Magenta": "\u001b[35m",
    "Cyan": "\u001b[36m",
    "White": "\u001b[37m"
}


def printColored(string, *args):
    print("\033[1;32m" + string+'\033[0m', *args)


def printHeader(string, color="Red"):
    print("\n" + colors[color]+string+'\033[0m'+"\n")
