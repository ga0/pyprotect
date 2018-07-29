# pyprotect

**pyprotect** is a lightweight python code protector, makes your python project harder to reverse engineer.

## Features

* Cross platform
* No need to install any extra dependents
* Very easy to use

***Only python3.x is supported by current version***

## Build pyprotect

* Download [pybind11](https://github.com/pybind/pybind11/releases) library:

1. Create a directory "deps" in pyprotect root directory.
2. Download pybind11 project into the newly created deps directory.
3. Unzip pybind11 zip file, and change the extracted directory's name from something like "pybind11-x.x.x" to "pybind11"

* Run these commands in pyprotect root directory:

```
mkdir build
cd build && cmake .. && make
```

And you can find ***libpyprotect.cpython-PYVERSION-PLATFORM.so*** in the objs directory.


## Encrypt your python project

Command:

```bash
python encrypt.py -s SCRIPTS_DIR -e ENTRY_POINT_LIST -o OUTPUT_DIR [--exclude EXCLUDED_SCRIPT_LIST]
```

***SCRIPTS_DIR*** is your python project root directory.  
***ENTRY_POINT_LIST*** is a comma separated list of file function pair which is directly ran as the entry point of your programme.
For example "app.py:main,test_app.py:run_test".  
***OUTPUT_DIR*** is the destination directory to store the encrypted python scripts.  
***EXCLUDED_SCRIPT_LIST*** is a comma separated list of python scripts which you don't wan to encrypt.

You need to put ***libpyprotect.cpython-PYVERSION-PLATFORM.so*** into the ***OUTPUT_DIR*** as part of your programme.

## Configuration [IMPORTANT]

For security reason you should change the AES key and IV, which is used to encrypt/decrypt the python scripts, to a stronger value.
And you may want to change the file extension of encrypted python scripts (which is ".pye" by default).

You can find these macros or variables in ***config.h*** and ***encrypt.py***:

* ***PYPROTECT_KEY***
* ***PYPROTECT_IV***
* ***PYPROTECT_EXT_NAME***

You need to change the two files both.
***Please change the PYPROTECT_KEY and PYPROTECT_IV to a safer value.***

## Roadmap

- [x] Support python3 scripts
- [ ] Support python2.7 scripts
- [ ] Anti debugging
- [ ] Software license control

## License

**pyprotect** is provided under a BSD-style license that can be found in the LICENSE file. By using, distributing, or contributing to this project, you agree to the terms and conditions of this license.