# 📤 autojs-unpacker
This is a reverse engineering tool for Android AutoJS application. It can decrypt js files in the `project` directory and re-encrypt them.

## Feature

- [x] decrypt a single file
- [x] encrypt a single file
- [x] decrypt/encrypt all files in the project directory

## Usage

- First, make your android device connected to your computer by usb. 

- Second, make sure that the applicaion you want to decrypt is running. 
- Follow the usage: 

```
usage: unpacker.py [-h] -p PKG [-id INPUT_DIR] [-od OUTPUT_DIR] [-if INPUT_FILE] [-of OUTPUT_FILE] [--ismain] {e,d}

             _        _                                        _             
  __ _ _   _| |_ ___ (_)___       _   _ _ __  _ __   __ _  ___| | _____ _ __ 
 / _` | | | | __/ _ \| / __|_____| | | | '_ \| '_ \ / _` |/ __| |/ / _ \ '__|
| (_| | |_| | || (_) | \__ \_____| |_| | | | | |_) | (_| | (__|   <  __/ |   
 \__,_|\__,_|\__\___// |___/      \__,_|_| |_| .__/ \__,_|\___|_|\_\___|_|   
                   |__/                      |_|                             
                                                                    by: imlk
https://github.com/KB5201314/autojs-unpacker

positional arguments:
  {e,d}            choose encrypt or decrypt

optional arguments:
  -h, --help       show this help message and exit
  -p PKG           package name or process name in android device to be attached
  -id INPUT_DIR    directory of input files
  -od OUTPUT_DIR   directory of output files
  -if INPUT_FILE   directory of single input file
  -of OUTPUT_FILE  directory of single output file
  --ismain         whether the file to be encrypted specified by -if is an entry(main) script
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
