#!/bin/python

import frida
import argparse
import time
import os
import sys
import datetime
from shutil import copyfile
import json
from argparse import RawTextHelpFormatter
from frida_tools.application import ConsoleApplication
import traceback

# TODO
# - [x] speed up Java --json-> js Data pass (main.js 130ms)
# - [] speed up js --base64-> java Data pass (main.js 1000ms, js base64 encode is too slow)


description='''%prog -m {e,d,l} -p PKG [other arguments]
             _        _                                        _             
  __ _ _   _| |_ ___ (_)___       _   _ _ __  _ __   __ _  ___| | _____ _ __ 
 / _` | | | | __/ _ \| / __|_____| | | | '_ \| '_ \ / _` |/ __| |/ / _ \ '__|
| (_| | |_| | || (_) | \__ \_____| |_| | | | | |_) | (_| | (__|   <  __/ |   
 \__,_|\__,_|\__\___// |___/      \__,_|_| |_| .__/ \__,_|\___|_|\_\___|_|   
                   |__/                      |_|                             
                                                                    by: imlk
https://github.com/KB5201314/autojs-unpacker
'''

magic_num_main="\x77\x01\x17\x7f\x12\x12\x00\x01"
magic_num_normal="\x77\x01\x17\x7f\x12\x12\x00\x00"


class AutoJSUnpackerApplication(ConsoleApplication):
    def _usage(self):
        return description

    def _add_options(self, parser):
        # parser.formatter_class = RawTextHelpFormatter
        parser.add_option('-m', '--mode', action="store", choices=['e', 'd', 'l'], type='choice', help='choose "e" for encrypt, or "d" for decrypt, or  for load')
        parser.add_option('-p', '--pkg', action="store", dest='pkg', type=str, help='package name or process name in android device to be attached')
        parser.add_option('--id', action="store", dest='input_dir', type=str, help='directory of input files. entry js file(e.g main.js) will not be recognized if project.json not in this directory')
        parser.add_option('--od', action="store", dest='output_dir', type=str, help='directory of output files')
        parser.add_option('--if', action="store", dest='input_file', type=str, help='directory of single input file')
        parser.add_option('--of', action="store", dest='output_file', type=str, help='directory of single output file')
        parser.add_option('--isui', action="store_true", dest='is_ui_file', default=False, help='whether the file to be encrypted specified by -if is an ui script')

    def _initialize(self, parser, options, args):
        self.options = options
        if not self.options.mode:
            print('argument -m/--mode must be specified ')
            self._exit(-1)
        if not self.options.pkg:
            print('argument -p/--pkg must be specified ')
            self._exit(-1)
        self.pkg = self.options.pkg
        self.opt_read_from_file = self.options.input_file or self.options.output_file
        if self.options.input_dir or self.options.output_dir:
            if self.opt_read_from_file:
                print('arguments -if/-of and -id/-od can not be specified at the same time')
                self._exit(-1)
        else:
            if not self.opt_read_from_file:
                print('arguments -if/-of or -id/-od must be specified')
                self._exit(-1)

        if (self.options.input_file or self.options.output_file) and not (self.options.input_file and self.options.output_file):
            print('arguments -if and -of must be specified at the same time')
            self._exit(-1)

        if (self.options.input_dir or self.options.output_dir) and not (self.options.input_dir and self.options.output_dir):
            print('arguments -id and -od must be specified at the same time')
            self._exit(-1)

    def _needs_device(self):
        return True

    def _start(self):
        try:
            try:
                try:
                    session = self._device.attach(self.pkg)
                except frida.ProcessNotFoundError:
                    session = self._device.attach(self.pkg + ":script")
            except frida.ProcessNotFoundError as e:
                print('[error] {}'.format(e))
                print('[error] Please make sure the target APP is running.')
                print('[error] Or you may not have selected a android device, try -U if your Android device is connected by USB.')
                self._exit(1)
                return

            script_str = open(os.path.dirname(__file__) + '/payload.js').read()
            self.script = session.create_script(script_str)
            self.script.load()


            if self.opt_read_from_file:
                if self.options.mode == 'd':
                    self.decrypt_file(self.options.input_file, self.options.output_file)
                elif self.options.mode == 'e':
                    self.encrypt_file(self.options.input_file, self.options.output_file, is_main=(self.opt_read_from_file and self.options.is_ui_file))
                elif self.options.mode == 'l':
                    self.encrypt_file_and_load(self.options.input_file, self.options.output_file, is_main=(self.opt_read_from_file and self.options.is_ui_file))

            else: # from project directory
                try:
                    main_file = json.load(open(os.path.join(self.options.input_dir,'./project.json'),'r'))['main']
                    main_file = os.path.normpath(os.path.join(self.options.input_dir,main_file))
                except:
                    print('[warning] cannot found project.json in {}, entry js file(e.g main.js) cannot be recognized'.format(self.options.input_dir), flush=True)
                    main_file = ""

                if not os.path.exists(self.options.output_dir):
                    os.makedirs(self.options.output_dir)
                for dirpath, dirnames, filenames in os.walk(self.options.input_dir):
                    dirpath_from_inputdir = os.path.relpath(dirpath, start=self.options.input_dir)
                    for name in filenames:
                        src_file = os.path.normpath(os.path.join(dirpath, name))
                        des_file = os.path.normpath(os.path.join(self.options.output_dir, dirpath_from_inputdir, name))
                        # print('{} -> {}'.format(src_file, des_file))
                        if name.endswith('.js'):
                            if self.options.mode == 'd':
                                self.decrypt_file(src_file, des_file)
                            elif self.options.mode == 'e':
                                self.encrypt_file(src_file, des_file, is_main=main_file==src_file)
                        else:
                            copyfile(src_file, des_file)
                    for name in dirnames:
                        dir = os.path.join(self.options.output_dir, dirpath_from_inputdir, name)
                        if not os.path.exists(dir):
                            os.makedirs(dir)
            self._exit(0)
        except BaseException as e:
            traceback.print_exc()
            msg = e.__str__() # TypeError: __str__ returned non-string (type NoneType)
            if msg:
                print('[error] {}'.format(msg))
            self._exit(1)


    def read_file_to_bytes(self, file_path):
        return list(open(file_path,'rb').read())


    def save_bytes_to_file(self, file_path, bs):
        dirname = os.path.dirname(file_path)
        if not os.path.isdir(dirname):
            os.makedirs(os.path.dirname(file_path))
        return open(file_path,'wb').write(bytes(list(map(lambda x:(x+256)%256, bs))))


    def decrypt_file(self, input_file, output_file):
        print('[decrypt] {} -> {}'.format(input_file, output_file), flush=True, end='')
        bs = self.read_file_to_bytes(input_file)
        bs_new = self.script.exports.decrypt(bs)
        self.save_bytes_to_file(output_file, bs_new)
        print('\t\tOK')


    def encrypt_file(self, input_file, output_file, is_main=False):
        print('[encrypt] {} -> {}'.format(input_file, output_file), flush=True, end='')
        bs = self.read_file_to_bytes(input_file)
        bs_new = self.script.exports.encrypt(bs)
        if is_main:
            bs_new = list(bytes(magic_num_main, encoding='utf-8')) + bs_new
        else:
            bs_new = list(bytes(magic_num_normal, encoding='utf-8')) + bs_new
        self.save_bytes_to_file(output_file, bs_new)
        print('\t\tOK')


    def encrypt_file_and_load(self, input_file, file_relative_path, is_main=False):
        file_relative_path = os.path.normpath(file_relative_path)
        print('[load] {} -> (data){}'.format(input_file, file_relative_path), flush=True, end='')
        bs = self.read_file_to_bytes(input_file)
        bs_new = self.script.exports.encrypt(bs)
        if is_main:
            bs_new = list(bytes(magic_num_main, encoding='utf-8')) + bs_new
        else:
            bs_new = list(bytes(magic_num_normal, encoding='utf-8')) + bs_new
        self.write_project_dir_in_device(file_relative_path, bs_new)
        print('\t\tOK')

        print('[restart] {}'.format(self.pkg), flush=True, end='')
        self.execute_cmd(['/system/bin/sh', '/system/bin/am', 'force-stop', self.pkg])
        time.sleep(1)
        self.execute_cmd(['/system/bin/sh', '/system/bin/settings', 'put', 'secure', 'enabled_accessibility_services', self.pkg + '/com.stardust.autojs.core.accessibility.AccessibilityService'])
        self.execute_cmd(['/system/bin/sh', '/system/bin/monkey', '-p', self.pkg, '1'])
        print('\t\tOK')

    def get_project_dir_in_device(self):
        return self.script.exports.getprojectpath()

    def write_project_dir_in_device(self, relative_path, data):
        full_path = self.get_project_dir_in_device() + '/project/' + relative_path
        self.script.exports.writefile(full_path, list(map(lambda x:(x+256)%256, data)))

    def execute_cmd(self,cmd):
        pid = self._device.spawn(cmd)
        self._device.resume(pid)

if __name__ == '__main__':
    app = AutoJSUnpackerApplication()
    app.run()