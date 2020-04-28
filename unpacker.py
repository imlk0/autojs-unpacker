#!/bin/python

import frida
import argparse
import os
import sys
import datetime
from shutil import copyfile
import json
from argparse import RawTextHelpFormatter

# TODO
# - [x] speed up Java --json-> js Data pass (main.js 130ms)
# - [] speed up js --base64-> java Data pass (main.js 1000ms, js base64 encode is too slow)


description='''
             _        _                                        _             
  __ _ _   _| |_ ___ (_)___       _   _ _ __  _ __   __ _  ___| | _____ _ __ 
 / _` | | | | __/ _ \| / __|_____| | | | '_ \| '_ \ / _` |/ __| |/ / _ \ '__|
| (_| | |_| | || (_) | \__ \_____| |_| | | | | |_) | (_| | (__|   <  __/ |   
 \__,_|\__,_|\__\___// |___/      \__,_|_| |_| .__/ \__,_|\___|_|\_\___|_|   
                   |__/                      |_|                             
                                                                    by: imlk
https://github.com/KB5201314/autojs-unpacker
'''

parser = argparse.ArgumentParser(description=description, formatter_class=RawTextHelpFormatter)

parser.add_argument('mode', action="store", choices=['e', 'd'], help='choose encrypt or decrypt', type=str)
parser.add_argument('-p', action="store", dest='pkg', type=str, required=True, help='package name or process name in android device to be attached')
parser.add_argument('-id', action="store", dest='input_dir', type=str, help='directory of input files')
parser.add_argument('-od', action="store", dest='output_dir', type=str, help='directory of output files')
parser.add_argument('-if', action="store", dest='input_file', type=str, help='directory of single input file')
parser.add_argument('-of', action="store", dest='output_file', type=str, help='directory of single output file')
parser.add_argument('--ismain', action="store_true", dest='is_main_file', default=False, help='whether the file to be encrypted specified by -if is an entry(main) script')

args = parser.parse_args()

magic_num_main="\x77\x01\x17\x7f\x12\x12\x00\x01"
magic_num_normal="\x77\x01\x17\x7f\x12\x12\x00\x00"

opt_read_from_file = args.input_file or args.output_file
if args.input_dir or args.output_dir:
    if opt_read_from_file:
        print('arguments -if/-of and -id/-od can not be specified at the same time')
        exit(-1)
else:
    if not opt_read_from_file:
        print('arguments -if/-of or -id/-od must be specified')
        exit(-1)

if (args.input_file or args.output_file) and not (args.input_file and args.output_file):
    print('arguments -if and -of must be specified at the same time')
    exit(-1)

if (args.input_dir or args.output_dir) and not (args.input_dir and args.output_dir):
    print('arguments -id and -od must be specified at the same time')
    exit(-1)


def read_file_to_bytes(file_path):
    return list(open(file_path,'rb').read())


def save_bytes_to_file(file_path, bs):
    dirname = os.path.dirname(file_path)
    if not os.path.isdir(dirname):
        os.makedirs(os.path.dirname(file_path))
    return open(file_path,'wb').write(bytes(list(map(lambda x:(x+256)%256, bs))))


def decrypt_file(input_file, output_file):
    print('[decrypt] {} -> {}'.format(input_file, output_file), flush=True, end='')
    bs = read_file_to_bytes(input_file)
    bs_new = script.exports.decrypt(bs)
    save_bytes_to_file(output_file, bs_new)
    print('\t\tOK')


def encrypt_file(input_file, output_file, is_main=False):
    print('[encrypt] {} -> {}'.format(input_file, output_file), flush=True, end='')
    bs = read_file_to_bytes(input_file)
    bs_new = script.exports.encrypt(bs)
    if is_main:
        bs_new = list(bytes(magic_num_main, encoding='utf-8')) + bs_new
    else:
        bs_new = list(bytes(magic_num_normal, encoding='utf-8')) + bs_new
    save_bytes_to_file(output_file, bs_new)
    print('\t\tOK')


device = frida.get_usb_device()
session = device.attach(args.pkg)
script_str=''
script_str = script_str + '\n' + (open(os.path.dirname(__file__) + '/payload.js').read())
script = session.create_script(script_str)
script.load()


if opt_read_from_file:
    if args.mode == 'd':
        decrypt_file(args.input_file, args.output_file)
    elif args.mode == 'e':
        encrypt_file(args.input_file, args.output_file, is_main=(opt_read_from_file and args.is_main_file))
else: # from project directory
    main_file = json.load(open(os.path.join(args.input_dir,'./project.json'),'r'))['main']
    main_file = os.path.normpath(os.path.join(args.input_dir,main_file))

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    for dirpath, dirnames, filenames in os.walk(args.input_dir):
        dirpath_from_inputdir = os.path.relpath(dirpath, start=args.input_dir)
        for name in filenames:
            src_file = os.path.normpath(os.path.join(dirpath, name))
            des_file = os.path.normpath(os.path.join(args.output_dir, dirpath_from_inputdir, name))
            # print('{} -> {}'.format(src_file, des_file))
            if name.endswith('.js'):
                if args.mode == 'd':
                    decrypt_file(src_file, des_file)
                elif args.mode == 'e':
                    encrypt_file(src_file, des_file, is_main=main_file==src_file)
            else:
                copyfile(src_file, des_file)
        for name in dirnames:
            dir = os.path.join(args.output_dir, dirpath_from_inputdir, name)
            if not os.path.exists(dir):
                os.makedirs(dir)
