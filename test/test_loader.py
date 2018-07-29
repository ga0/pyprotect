import sys
import os
import shutil

if __name__ == '__main__':
    # 1. encrypt app
    sys.path.append(os.path.join(os.getcwd(), '..'))

    from encrypt import encrypt_tree

    srcroot = os.path.join(os.getcwd(), 'app')
    entrances = [(os.path.normpath(os.path.join(srcroot, 'app.py')), 'main')]
    destroot = os.path.join(os.getcwd(), 'dest')
    excludes = [os.path.normpath(os.path.join(srcroot, 'exclude.py'))]
    encrypt_tree(srcroot, entrances, destroot, excludes)

