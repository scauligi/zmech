import sys

from .zmech import ZMech

if __name__ == '__main__':
    if len(sys.argv) > 1:
        z = ZMech(sys.argv[1])
        z.load()
