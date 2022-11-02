#!/usr/bin/env python
# coding: utf-8 

from __future__ import unicode_literals

import argparse
import json
import logging
import qrcode
import secrets
import sys

from logging.handlers import RotatingFileHandler
from otpauth import OtpAuth

def _generate(logger, secret, code, name, description):
    try:
        secret = secrets.token_hex(40);
        auth = OtpAuth(secret);
        s = auth.to_uri('totp', description, name);
        img = qrcode.make(s);
        img.show();
        print('SECURITY WARNING - keep the secret key:', secret)
        logger.warning("Secret totp is generated.");
        sys.exit(0);

    except Exception as e:
        print(str(e));
        logger.error(str(e));
        sys.exit(4);

def _verify(logger, secret, code, name, description):
    try:
        auth = OtpAuth(secret);

        if auth.valid_totp(code):
            print("ACCEPT");
            logger.info("Time based code verify is success.");
            sys.exit(0);

        else:
            print("FAIL");
            logger.info("Time based code verify is failed.");
            sys.exit(1);

    except Exception as e:
        print(str(e)); 
        logger.error(str(e));
        sys.exit(4);


def _logging(level, logfile=''):
    logger = logging.getLogger()
    logger.setLevel(level)
   
    if logfile is not None:
        file_handler = RotatingFileHandler(logfile, 'a', 1000000, 1)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)
        
        formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')

        file_handler.setFormatter(formatter)
     
    steam_handler = logging.StreamHandler()
    steam_handler.setLevel(level)
    logger.addHandler(steam_handler)

    formatter = logging.Formatter('%(levelname)s :: %(message)s')
    
    steam_handler.setFormatter(formatter)
    return logger

def _main(argv):
    LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}

    FUNCTION_MAP = {'generate' : _generate, 
                    'verify'  : _verify}


    parser = argparse.ArgumentParser(description="'totpverify.py' - totp verify with google authenticator.")
    parser.add_argument("-l",
                        "--level",
                        dest="level",
                        required=False, 
                        help="specify the logs's level", 
                        metavar="LEVEL",
                        type=str, 
                        choices=LEVELS.keys(),
                        default="error")
    parser.add_argument("-L",
                        "--logfile",
                        dest="logfile",
                        required=False, 
                        help="specify the path logs's level", 
                        metavar="LOGFILE",
                        type=str)
    parser.add_argument("-a",
                        "--action",
                        dest="action",
                        required=False, 
                        help="specify the action import or export configuration Apache Nifi", 
                        metavar="ACTION",
                        type=str, 
                        choices=FUNCTION_MAP.keys(),
                        default="generate")
    parser.add_argument("-c",
                        "--code",
                        dest="code",
                        required=False,
                        help="validate time based code",
                        metavar="CODE",
                        type=int)
    parser.add_argument("-s",
                        "--secret",
                        dest="secret",
                        required=False,
                        help="a secret string",
                        metavar="SECRET",
                        type=str)
    parser.add_argument("-n",
                        "--name",
                        dest="name",
                        required=False,
                        help="totp name",
                        metavar="NAME",
                        type=str)
    parser.add_argument("-d",
                        "--description",
                        dest="description",
                        required=False,
                        help="totp description",
                        metavar="DESCRIPTION",
                        type=str)

    args = parser.parse_args()

    logger = _logging(LEVELS[args.level], args.logfile)  

    FUNCTION_MAP[args.action](logger, args.secret, args.code, args.name, args.description)
    pass

if __name__ == "__main__":
    _main(sys.argv)
