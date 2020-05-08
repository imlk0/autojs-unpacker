# 📤 autojs-unpacker
这是基于frida的针对AutoJS应用程序的逆向工程工具。 它可以解密`project`目录中的js文件，并且支持重新加密。

## 特性
- [x] 解密单个文件
- [x] 加密单个文件
- [x] 解密/加密项目目录中的所有文件
- [x] 支持将app运行在模拟器中
- [ ] 支持"encryptLevel": 1之外的其它加密
- [x] 增加修改js代码后免重新打包动态加载（想法是改完js后adb push到相应的/data/data/com.example.pkg/files/project/目录，然后重启应用）


## 前置要求
- 设备被root（因为frida要求要以root权限启动frida-server）

## 参数说明：
- `-h` 打印帮助信息
- **`-U` 连接到一个usb设备或者Android官方模拟器（大部分情况下，会需要该参数，否则默认会是选择当前电脑）**
   > 在有多种设备的情况下，你也可以通过其它方式指定目标设备，如用`-D emulator-5554`连接到id为`emulator-5554`的设备。设备id可以用`frida-ls-devices`查看
   > 本工具用于选择设备的参数与`frida-ps`工具相同，具体可看`-h`选项的输出结果
- `-m` 后接字母d表示解密，接e表示加密
- `-p` 指示目标app的包名
- `--if`、`--of` 输入输出文件的路径
- `--id`、`--od` 递归解密/加密project文件夹时，输入文件夹和产生结果的文件夹
- `--isui` 加密单个文件时，指示是否为使用ui界面的js文件，一般app的入口js文件会是个使用ui的js文件（这个在project.json中有指定，一般是main.js，加密时需要给使用到ui界面的文件加上特殊的文件头，否则将以脚本模式解释执行）

```
Usage: unpacker.py -m {e,d,l} -p PKG [other arguments]
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
  -m MODE, --mode=MODE  choose "e" for encrypt, or "d" for decrypt, or  for
                        load
  -p PKG, --pkg=PKG     package name or process name in android device to be
                        attached
  --id=INPUT_DIR        directory of input files. entry js file(e.g main.js)
                        will not be recognized if project.json not in this
                        directory
  --od=OUTPUT_DIR       directory of output files
  --if=INPUT_FILE       directory of single input file
  --of=OUTPUT_FILE      directory of single output file
  --isui                whether the file to be encrypted specified by -if is
                        an ui scripto
```


## 用法
1-2步是frida环境的搭建过程，frida官方有相关文档[https://frida.re/docs/android/](https://frida.re/docs/android/) 网上也有一些别人写的教程，这里我就不啰嗦了简单写一写
**在运行本工具前，请务必确保frida官方提供的工具（如frida-ps之类的）在你的环境中已经能够运行**。

1. 通过pip安装`frida`

   ```shell
   pip install frida
   ```

2. 通过USB将您的android设备连接到计算机，或启动一个Android模拟器，并以root用户启动`frida-server`。
    > frida是一种CS架构，在目标Android机器上运行一个`frida-server`后，本机可以连接到该server，然后借助该server来完成一系列操作。

    首先从[https://github.com/frida/frida/releases](https://github.com/frida/frida/releases)这里下载一个`frida-server`文件，比如我们的目标环境是Android，并且是arm设备，我们就下载一个[frida-server-12.8.20-android-arm.xz](https://github.com/frida/frida/releases/download/12.8.20/frida-server-12.8.20-android-arm.xz)

    下载完成解压缩重命名成`frida-server`，我们首先在shell中进入该文件所在目录，用adb push到目标机器上

    ```shell
    adb push ./frida-server /data/local/tmp/
    ```

    然后执行：

    ```shell
    adb shell su -c /data/local/tmp/frida-server
    ```

    切记不要关闭当前shell
   
    试一下在本机执行frida提供的工具`frida-ps -U`，如果能看到输出说明环境已经搭建好了。

**下面进入本工具的使用部分**
该工具由`unpacker.py`和`payload.js`两个部分组成，前者负责连接目标机器和处理文件，后者被前者加载到目标机器中负责加密解密。
原理是：
读取待解密的js文件内容，然后借助frida调用待破解的app中存在的解密函数，并将待解密数据作为参数，最后获取解密后的数据保存到本机上方便编辑。
编辑完以后用类似的过程调用加密函数，把改完的js文件加密回去。


3. clone或网页下载本仓库到本机任意目录下，然后在shell中进入该目录

   ```shell
   git clone git@github.com:KB5201314/autojs-unpacker.git
   cd autojs-unpacker
   ```

5. 在本机上解压目标apk（其实我们是想解密apk里`assets/project/`目录下的文件）

6. 在手机上启动目标应用程序，确保它正在运行。


7. 举例解密一个`main.js`：

   ```shell
   ./unpacker.py -U -m d -p com.example.pkg --if ./unzip/assets/project/main.js --of ./src/main.js
   # 解释：
   # ./unpacker.py是脚本的路径
   # -U 表示连接到USB设备或Android官方模拟器，
   # -m d 表示decrypt，解密模式
   # -p com.example.pkg 是指定包名
   # --if ./unzip/assets/project/main.js 是本机上的输入文件路径为./unzip/assets/project/main.js
   # --of ./src/main.js 是指定解密结果输出到本机上的./src/main.js这个路径
   ```

   你将看到这样的输出，说明文件已经被解密到`./src/main.js`：

   ```
   [decrypt] ./unzip/assets/project/main.js -> ./src/main.js               OK
   ```


8. 按照你的意愿对`./src/main.js`的逻辑进行修改


8. 重新加密该文件：加密`./src/main.js`，输出文件为`./en/main.js`

   ```shell
   ./unpacker.py -U -m e -p com.example.pkg --if ./src/main.js --of ./en/main.js --ismain
   # 模式改成e, 即encrypt，加密模式
   # 由于该文件是使用ui的js文件，它有一个独特的文件头，加密时请指定参数--isui
   ```

   你将看到这样的输出，说明加密成功：

   ```
   [encrypt] ./src/main.js -> ./en/main.js         OK
   ```

9. 替换apk中的文件：

   用任意压缩工具打开原始apk，将你修改过且重新加密后的文件替换掉对应的原js文件

10. 对修改后的apk文件重新签名，安装运行


## Examples
- 解密一个文件
```shell
# decrypt ./assets/project/main.js to ./src/main.js
./unpacker.py -U -m d -p com.example.pkg --if ./assets/project/main.js --of ./src/main.js
```

- 加密普通js文件
```shell
# encrypt ./src/util.js to ./en/util.js
./unpacker.py -U -m e -p com.example.pkg --if ./src/util.js --of ./en/util.js
```

- 加密使用ui的js文件
```shell
# encrypt ./src/main.js to ./en/main.js
./unpacker.py -U -m e -p com.example.pkg --if ./src/main.js --of ./en/main.js --ismain
```

- 递归解密project目录的所有js文件
```shell
# decrypt ./assets/project/ to ./src/
./unpacker.py -U -m d -p com.example.pkg --id ./assets/project/ --od ./src/
```

## 常见问题
1. 弹Toast提示"Error:: 语法错误 (main.js#1)"
   