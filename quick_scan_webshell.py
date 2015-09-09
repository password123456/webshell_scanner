"""
 WebShell Scanner Based on patterns.
 created by password123456.
"""
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import codecs
import argparse
import re
import hashlib

def GET_FILEINFO(filename):
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(filename)
    print '\n'
    print ('=' * 70)
    print ' + File         : ' + os.path.abspath(filename)
    print ' + File Owner   : ' + str(uid) + ':' + str(gid)
    print ' + Permission   : ' + oct(mode)[-3:]
    print ' + Last accessed: ' + time.ctime(atime)
    print ' + Last modified: ' + time.ctime(mtime)
    print ' + Filesize     : ' + GET_FILESIZE(filename)
    print ' + MD5          : ' + GET_FILEHASH(filename, 'md5')
    print ' + SHA1         : ' + GET_FILEHASH(filename, 'sha1')
    print ' + SHA256       : ' + GET_FILEHASH(filename, 'sha256')

def GET_FILESIZE(filename):
    n = os.path.getsize(filename)
    if n < 1024.0:
        a = str(n) + " bytes"
        return a
    n = n/1024
    a = str(n) + " KB"
    return a

def GET_FILEHASH(filename, hash):
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

def DO_SCAN_CHINESE(filename):
    global ichinese_words_count

    f = codecs.open(filename, 'r', 'utf-8')
    ichinese_words_count = 0
    bchinese_detect = 0

    for n,line in enumerate(f.read().split('\n')):
        n += 1
        if re.findall(ur'[\u4e00-\u9fff]+', line):
            bchinese_detect = 1
            ichinese_words_count += 1
            #print "line:", n, line
    f.close()

    if bchinese_detect >= 1:
        print ' [*] Scan Chinese Words : [ count /',ichinese_words_count,']'
    else:
        print ' [*] Scan Chinese Words : [ count /',ichinese_words_count,']'

def DO_SCAN_WEBSHELL(filename):
    global iphp_detect_count
    global iasp_detect_count
    global ijsp_detect_count

    PHP_SIGS = r"^(?si)(\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem \
                        |\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b \
                        |\bshow_source\b|\b687474703a2f2f377368656c6c2e676f6f676c65636f64652e636f6d2f73766e2f6d616b652e6a7067\b \
                        |\buniqid\b|\bec38fe2a8497e0a8d6d349b3533038cb\b|\b88f078ec861a3e4baeb858e1b4308ef0\b|\bTBNnGMfflrqBFnaes\b \
                        |\bx50\\x4b\\x05\\x06\\x00\\x00\\x00\\x00\b|\bx50\\x4b\\x03\\x04\\x0a\b|\b9c3a9720372fdfac053882f578e65846\b \
                        |\bshell\b|\bXSLTProcessor\b|\bWebShell\b|\berror_reporting\b|\beditfile\b|\backdoor\b|\betc\/\passwd\b|\betc\/\shadow\b \
                        |\bmysql_query\b|\bphpinfo\b|\bcgi-script\b|\bgethostbyname\b|\bphp.ini\b|\bmysql.user\b|\bbash_history\b \
                        |\bSHOW\s*FIELDS\s*FROM\b|\bmysqladmin\b|\bSERVER_ADMIN\b|\bDOCUMENT_ROOT\b|\bGRANT\s*ALL\s*PRIVILEGES\b \
                        |\bgetcwd\b|\bHTTP_HOST\b|\bdisplay_errors\b|\ballow_url_fopen\b|\bbase_convert\b \
                        |\b7b24afc8bc80e548d66c4e7ff72171c5\b|\bgcc\s*-o\b)"

    ASP_SIGS = r"(?si)(\bsystem32\b|\bcmd.exe\b|\bFromBase64String\b|\bSCRIPT\s*RUNAT=SERVER\b|\bs*LANGUAGE=JAVASCRIPT\b \
                       |\bPublicKeyToken=B03F5F7F11D50A3A\b|\bServer.ScriptTimeout\b|\bclsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\b \
                       |\bclsid:72C24DD5-D70A-438B-8A42-98424B88AFB8\b|20132165414621325641311254123112512\b|\bmssql导库\b \
                       |\bmssql\s*database\s*export\b|\b1c1f81a8b0a630f530f52fa9aa9dda1b\b|\bgif89a\b|\bWebSniff(.*?)Powered\s*by\b \
                       |\bF4ckTeam\b|\bdownload\s*file\b|\bsilicname\b|\bsilicpass\b|\bserver.mappath\b|\bVBScript.Encode\b \
                       |\bkernel32.dll\b|\bDirectoryInfo\b|\bF4ck\b|\bHKEY_LOCAL_MACHINE\\SYSTEM\b|\bServices\\Tcpip\\EnableSecurityFilters\b \
                       |\b\\hzhost\\config\\settings\\mastersvrpass\b|\b\\Microsoft\\SchedulingAgent\\LogPath\b|\bwsh.regRead\b \
                       |\bwsh.regWrite\b|\bwsh.regDelete\b|\b\\Terminal\s*Server\\Wds\\rdpwd\\Tds\\tcp\\PortNumber\b|\bXP_REGWRITE\b \
                       |\bXP_REGREAD\b|\bXP_CMDSHELL\b|\bMICROSOFT.JET.OLEDB\b|\bHKEY_CURRENT_USER\b|\bmiemie\b|\bWWWRoot\b \
                       |\bFolderPath\b|\bGetFile\b|\bserver.scripttimeout\b|\bserver_software\b|\bCONST_FSO\b|\bRQSFileManager\b \
                       |\bWINDOWS\\\TEMP\b|\bpass=request\b|\bclientPassword\b|\bREG_DWORD\b|\bREG_BINARY\b|\bREG_EXPAND_SZ\b \
                       |\bSYSTEMROOT\b|\bWNetwork.ComputerName\b|\bWNetwork.ComputerName\b|\bScripting.FileSystemObject\b \
                       |\bCreateTextFile\b|\bbase64String\b|\bADODB.Connection\b|\b\w+Rootkit\b|\bsp_oacreate\b|\bSP_OAMethod\b \
                       |\bicesword\b|\bwindows\\temp\b|\bwindows\\system32\b)"


    JSP_SIGS = r"(?si)(\bchopper\b|\bjshell\b|\bJspSpyPwd\b|\bAlanwalker\b|\bcaicaihk\b|\bcaicaihk\b|\bJspSpy\b \
                      |\b6625108\b|\b1decc1ce886d1b2f9f91ecb39967832d05f8e8b8\b|\bJFolder\.jsp\b|\bMicrosoft\s*Access\s*Driver\b \
                      |\blocalhost:1433\b|\blocalhost:3306\b|\bSystem.getenv()\b|\bSystem.getProperties()\b|\bExecute\s*Command\b)"

    php_regex = re.compile(PHP_SIGS, flags=re.IGNORECASE)
    asp_regex = re.compile(ASP_SIGS, flags=re.IGNORECASE)
    jsp_regex = re.compile(JSP_SIGS, flags=re.IGNORECASE)

    f = open(filename, 'r')

    iphp_detect_count = 0
    iasp_detect_count = 0
    ijsp_detect_count = 0

    php_detect = 0
    asp_detect = 0
    jsp_detect = 0

    for n,line in enumerate(f.read().split('\n')):
        n += 1

        _php_match = re.findall(php_regex, line)
        _asp_match = re.findall(asp_regex, line)
        _jsp_match = re.findall(jsp_regex, line)

        if _php_match:
            php_detect = 1
            iphp_detect_count += 1
            _linecounter = 1

            for _line in line:
                _match_line = php_regex.findall(_line)

        if _asp_match:
            asp_detect = 1
            iasp_detect_count += 1
            _linecounter = 1

            for _line in line:
                _match_line = asp_regex.findall(_line)

        if _jsp_match:
            jsp_detect = 1
            ijsp_detect_count += 1
            _linecounter = 1

            for _line in line:
                _match_line = asp_regex.findall(_line)

    detect_result = php_detect + asp_detect + jsp_detect
    f.close()

    if detect_result >= 1 :
        GET_FILEINFO(filename)
        print '\n'
        print ' [*] PHP Suspicious function used: [count /',iphp_detect_count,']'
        print ' [*] ASP Suspicious function used: [count /',iasp_detect_count,']'
        print ' [*] JSP Suspicious function used: [count /',ijsp_detect_count,']'
        DO_SCAN_CHINESE(filename)
        SAVE_LOG(filename)

def SCAN_TEXTFILE(path):
    if os.path.exists(path):
	    for root, dirs, files in os.walk(path):
	        for filename in files:
	            file = os.path.realpath(os.path.join(root,filename))
	            try:
	                with open(file, 'rb') as f:
	                    if b'\x00' in f.read():
	                        #print('The file is binary! ', file)
	                        pass
	                    else:
	                        #print('The file is not binary! ', file)
	                        DO_SCAN_WEBSHELL(file)
	            except:
	                pass
    else:
        print "\n[-] [ %s ] not exits.! Check directory.!! " % (path)
        sys.exit()


def SAVE_LOG(filename):
    slog_date = time.strftime('%Y-%m-%d %H:%M:%S')
    sfile_path = os.path.abspath(filename)
    ssave_log =  time.strftime('%Y%m%d') + '_scan-log.txt'
    try:
        if os.path.exists(ssave_log):
           mode = 'a'
        else:
           mode = 'w'

        with open(ssave_log, mode) as f:
            f.write('[%s] PHP=%s | ASP=%s | JSP=%s | china=%s | %s \n' % (slog_date, iphp_detect_count, iasp_detect_count, ijsp_detect_count, ichinese_words_count, sfile_path))
    finally:
            f.close()

def main():
    opt=argparse.ArgumentParser(description="::::: Quick WebShell-Scan + Scan Chinese Words :::::")
    opt.add_argument("scan_path", help="ex) /var/www/html/upload")
    opt.add_argument("-p", "--path", action="store_true", dest="path", help="ex) python quick_scan_webshell_v0.1.py -p /var/www/html/upload")

    if len(sys.argv)<=2:
        opt.print_help()
        sys.exit(1)
    else:
        pass

    options= opt.parse_args()

    if options.path:
        path = os.path.abspath((options.scan_path))
        SCAN_TEXTFILE(path)
    else:
        opt.print_help()
        sys.exit()

if __name__ == '__main__':
    main()

