#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
 WebShell Scanner Based on patterns.
 created by password123456.
"""
import os,sys,time
import codecs
import argparse
import re
import hashlib

def get_fileinfo(filename):
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(filename)
    print '\n'
    print ('=' * 70)
    print ' + File         : ' + os.path.abspath(filename)
    print ' + File Owner   : ' + str(uid) + ':' + str(gid)
    print ' + Permission   : ' + oct(mode)[-3:]
    print ' + Last accessed: ' + time.ctime(atime)
    print ' + Last modified: ' + time.ctime(mtime)
    print ' + Filesize     : ' + get_filesize(filename)
    print ' + MD5          : ' + get_filehash(filename, 'md5')
    print ' + SHA1         : ' + get_filehash(filename, 'sha1')
    print ' + SHA256       : ' + get_filehash(filename, 'sha256')

def get_filesize(filename):
    n = os.path.getsize(filename)
    if n < 1024.0:
        a = str(n) + " bytes"
        return a
    n = n/1024
    a = str(n) + " KB"
    return a

def get_filehash(filename, hash):
    if hash in ('sha256', 'SHA256'):
        m = hashlib.sha256()
    elif hash in ('md5', 'MD5'):
        m = hashlib.md5()
    elif hash in ('sha1', 'SHA1'):
        m = hashlib.sha1()
    else:
        m = hashlib.md5()

    try:
        fh = open(filename, 'rb')
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()
    except IOError as err:
        print "Error:" + err.strerror
        sys.exit(1)



def do_scan_chinesse(filename):
    f = codecs.open(filename, 'r', 'utf-8')
    global chinese_words_counter
    chinese_words_counter = 1

    for n,line in enumerate(f.read().split('\n')):
        n += 1
        if re.findall(ur'[\u4e00-\u9fff]+', line):
            chinese_detect = 1
            chinese_words_counter += 1
            #print "line:", n, line
    f.close()

    if chinese_detect >= 1:
        print ' => Scan Chinese words : [count /', chinese_words_counter,']'
    else:
        print ' => Scan Chinese words : clean '

def do_scan_shell_sigs(filename):
    global php_detect_counter
    global asp_detect_counter
    global jsp_detect_counter

    PHP_SIGS = r"(?si)(preg_replace.*\/e|`.*?\$.*?`|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b|687474703a2f2f377368656c6c2e676f6f676c65636f64652e636f6d2f73766e2f6d616b652e6a7067|uniqid|ec38fe2a8497e0a8d6d349b3533038cb|88f078ec861a3e4baeb858e1b4308ef0|TBNnGMfflrqBFnaes|\\x50\\x4b\\x05\\x06\\x00\\x00\\x00\\x00|9c3a9720372fdfac053882f578e65846|shell)"

    ASP_SIGS = r"(?si)(\bsystem32\b|\bcmd.exe\b|FromBase64String|SCRIPT\s*RUNAT=SERVER\s*LANGUAGE=JAVASCRIPT|PublicKeyToken\\=B03F5F7F11D50A3A|\bServer.ScriptTimeout\b|\bclsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\b|clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8\b|20132165414621325641311254123112512|mssql导库|\bmssql database export\b|1c1f81a8b0a630f530f52fa9aa9dda1b|gif89|WebSniff(.*?)Powered\s*by|法客论坛|F4ckTeam|(?:ExecuteStatement)\(.*?request|#@~\^bGsBAA==@#@&AC13`DV{J@!8D@\*@!8D@\*@!\^n|\bdownload file\b|silicname|silicpass|命令行执行|server.mappath|VBScript.Encode|kernel32.dll|DirectoryInfo|F4ck|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)"

    JSP_SIGS = r"(?si)(chopper|jshell|JspSpyPwd|Alanwalker|caicaihk|caicaihk|Alanwalker|JspSpy|6625108|1decc1ce886d1b2f9f91ecb39967832d05f8e8b8|JFolder\.jsp)"

    php_regex = re.compile(PHP_SIGS, flags=re.IGNORECASE)
    asp_regex = re.compile(ASP_SIGS, flags=re.IGNORECASE)
    jsp_regex = re.compile(JSP_SIGS, flags=re.IGNORECASE)

    f = open(filename, 'r')
    php_detect_counter = 1
    asp_detect_counter = 1
    jsp_detect_counter = 1

    for n,line in enumerate(f.read().split('\n')):
        n += 1

        _php_match = re.findall(php_regex, line)
        _asp_match = re.findall(asp_regex, line)
        _jsp_match = re.findall(jsp_regex, line)

        if _php_match:
            php_detect = 1
            php_detect_counter += 1
            _linecounter = 1

            for _line in line:
                _match_line = php_regex.findall(_line)
            #print 'line:', n, line

        if _asp_match:
            asp_detect = 1
            asp_detect_counter += 1
            _linecounter = 1

            for _line in line:
                _match_line = asp_regex.findall(_line)

        if _jsp_match:
            jsp_detect = 1
            jsp_detect_counter += 1
            _linecounter = 1

            for _line in line:
                _match_line = asp_regex.findall(_line)

    f.close()

    detect_result = php_detect + asp_detect + jsp_detect

    if detect_result >= 1 :
        get_fileinfo(filename)
        print '\n'
        print ' [*] PHP Suspicious function used: [count /',php_detect_counter,']'
        print ' [*] ASP Suspicious function used: [count /',asp_detect_counter,']'
        print ' [*] JSP Suspicious function used: [count /',jsp_detect_counter,']'
        do_scan_chinesse(filename)
        print (':' * 20), '>> Suspicious file'

        log_file(filename)


def scan_filetype(path):
    print "Current Path: " + path

    for root, dirs, files in os.walk(path):
        for filename in files:
            file = os.path.realpath(os.path.join(root,filename))
            try:
                with open(file, 'rb') as f:
                    if b'\x00' in f.read():
                        #print('The file is binary! ', path)
                        continue
                    else:
                        #print('The file is not binary! ', filename)
                        do_scan_shell_sigs(file)
            except:
                pass

def log_file(filename):

    log_date = time.strftime('%Y-%m-%d %H:%M:%S')
    file_path = os.path.abspath(filename)
    log_file =  time.strftime('%Y%m%d') + '_scan-log.txt'

    mode = 'a' if os.path.exists(log_file) else 'w'
    with open(log_file, mode) as f:
        f.write('[%s] PHP=%s, ASP=%s, JSP=%s, china=%s, \t %s \n' % (log_date, php_detect_counter, asp_detect_counter, jsp_detect_counter, chinese_words_counter, file_path) )
        f.close()

def main():
  opt=argparse.ArgumentParser(description="::::: Quick WebShell-Scan + Scan Chinese Words :::::")
  opt.add_argument("scan_path", help="ex) /var/www/html/upload")
  opt.add_argument("-p", "--path", action="store_true", dest="path", help="ex) python quick_scan_webshell.py -p /var/www/html/upload")

  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)

  options= opt.parse_args()

  if options.path:
      path = os.path.abspath((options.scan_path))
      scan_filetype(path)

  else:
      opt.print_help()
      sys.exit()


if __name__ == '__main__':
    main()
