# 📤 autojs-unpacker
This is a reverse engineering tool for Android AutoJS application. It can decrypt js files in the `project` directory and re-encrypt them.

[中文文档](README_zh.md)

## Feature

- [x] decrypt a single file
- [x] encrypt a single file
- [x] decrypt/encrypt all files in the project directory

## Usage

- Clone this library to this machine, and make sure that `frida` has been installed via `pip`
- First, make your android device connected to your computer by usb, and start `frida-server` as root user. 
- Second, make sure that the applicaion you want to decrypt is running. 
- Follow the usage below:

```
Usage: unpacker.py -m {e,d} -p PKG [other arguments]
             _        _                                        _             
  __ _ _   _| |_ ___ (_)___       _   _ _ __  _ __   __ _  ___| | _____ _ __ 
 / _` | | | | __/ _ \| / __|_____| | | | '_ \| '_ \ / _` |/ __| |/ / _ \ '__|
| (_| | |_| | || (_) | \__ \_____| |_| | | | | |_) | (_| | (__|   <  __/ |   
 \__,_|\__,_|\__\___// |___/      \__,_|_| |_| .__/ \__,_|\___|_|\_\___|_|   
                   |__/                      |_|                             
                                                                    by: imlk
https://github.com/KB5201314/autojs-unpacker


Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -D ID, --device=ID    connect to device with the given ID
  -U, --usb             connect to USB device
  -R, --remote          connect to remote frida-server
  -H HOST, --host=HOST  connect to remote frida-server on HOST
  -O FILE, --options-file=FILE
                        text file containing additional command line options
  -m MODE, --mode=MODE  choose "e" for encrypt, or "d" for decrypt
  -p PKG, --pkg=PKG     package name or process name in android device to be
                        attached
  --id=INPUT_DIR        directory of input files. entry js file(e.g main.js)
                        will not be recognized if project.json not in this
                        directory
  --od=OUTPUT_DIR       directory of output files
  --if=INPUT_FILE       directory of single input file
  --of=OUTPUT_FILE      directory of single output file
  --ismain              whether the file to be encrypted specified by -if is
                        an entry(main) script
```

## Examples
- decrypt a file
```shell
# decrypt ./assets/project/main.js to ./src/main.js
./unpacker.py d -p com.example.pkg -if ./assets/project/main.js -of ./src/main.js
```
- encrypt a file
```shell
# encrypt ./src/main.js to ./src_en/main.js
./unpacker.py e -p com.example.pkg -if ./src/main.js -of ./src_en/main.js
```
