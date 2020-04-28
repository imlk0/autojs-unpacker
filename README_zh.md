# 📤 autojs-unpacker
这是基于frida的针对AutoJS应用程序的逆向工程工具。 它可以解密`project`目录中的js文件，并且支持重新加密。

## Feature

- [x] 解密单个文件
- [x] 加密单个文件
- [x] 解密/加密项目目录中的所有文件

## 用法
- 将本库clone到本机，且确保已通过pip安装`frida`
- 通过USB将您的android设备连接到计算机，并以root用户生成启动`frida-server`。
- 确保要解密的应用程序正在运行。
- 按照下面的`usage`来执行
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
