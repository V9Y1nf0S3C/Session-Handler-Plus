import re
import datetime
import subprocess
import threading

from burp import IBurpExtender, IHttpListener, ISessionHandlingAction, ICookie, ITab, IExtensionStateListener
from javax.swing import BorderFactory, JCheckBox, JLabel, JPanel, JScrollPane, BoxLayout, JTextField, JButton
from java.awt import GridLayout, GridBagConstraints, Insets, Cursor, Desktop, Color
from java.awt.event import MouseAdapter
from java.net import URI

VAL_ABOUT_SHP_MINI = 'Author: Vinaya Kumar      [GitHub: https://github.com/V9Y1nf0S3C/Session-Handler-Plus]      Purpose: Session handling for JWT/AccessToken/RefreshToken, run external scripts through SessionHandlingAction'
VAL_REF_LINK = 'https://github.com/V9Y1nf0S3C/Session-Handler-Plus'

EXT_VERSION = 'v1.0'
VAL_COOKIE_DOMAIN = 'localhost'
VAL_JWT_COOKIE_NAME = 'TOKEN-1'#'access_token'
VAL_REFRESH_TOKEN_COOKIE_NAME = 'TOKEN-2'#'refresh_token'

CHECK_PRINT_REJECT_LOGS_1A_1B = False
CHECK_REQ_URL_REGEX = True
VALUE_REQ_URL_REGEX = "/token$|/token\\?"
CHECK_RESP_CONTENT_TYPE = True
VALUE_RESP_CONTENT_TYPE_HEADER = "Content-Type: application/json"
CHECK_REQ_PATH = True
VALUE_REQ_PATH_HEADER = "SHP-Path:(.*)"
LISTEN_4_ACCESS_TOKEN = True
VALUE_READ_JWT_REGEX = "access_token\":\"(.+?)\""
LISTEN_4_REFRESH_TOKEN = True
VALUE_READ_REFRESH_TOKEN_REGEX = "refresh_token\":\"(.+?)\""
REPLACE_STRUCTURE_TOKEN1_HEAD_1 = "%s %s"
REPLACE_STRUCTURE_TOKEN1_HEAD_2 = "%s %s"
REPLACE_STRUCTURE_TOKEN1_BODY = "%s%s"

CHECK_TOKEN1_HEADER_1 = True
CHECK_TOKEN1_HEADER_2 = False
CHECK_TOKEN1_BODY = False
VAL_JWT_HEADER_NAME_1 = 'Authorization: Bearer'
VAL_JWT_HEADER_NAME_2 = 'custom-auth-gw:'
CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_1 = False
VAL_JWT_BODY_NAME_1 = "access_token=\\w+"
VAL_JWT_BODY_NAME_2 = "access_token="
CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_2 = False

CHECK_TOKEN2_HEADER = False
CHECK_TOKEN2_BODY = True
VAL_TOKEN2_HDR_PARAM_NAME_1 = 'My-Custom-Header: Prefix'
CHECK_TOKEN2_HEADER_ADD_IF_NOT_EXIST = False
VAL_TOKEN2_BODY_PARAM_NAME_1 = '&refresh_token=(.*?)$'
VAL_TOKEN2_BODY_PARAM_NAME_2 = "&refresh_token="
REPLACE_STRUCTURE_TOKEN2_HEAD = "%s %s"
REPLACE_STRUCTURE_TOKEN2_BODY = "%s%s"


SHA_CS1 = "SH+ Invoke Script 1"
SHA_CS2 = "SH+ Invoke Script 2"
SHA_CS3 = "SH+ Invoke Script 3"
SHA_DEL_ALL_CKS = "SH+ Delete All Cookies in BCJ"
SHA_DEL_LCH_CKS = "SH+ Delete {} Cookies in BCJ".format(VAL_COOKIE_DOMAIN)
SHA_MOD_JWT_TKN = "SH+ Replace Token-1"
SHA_MOD_REF_TKN = "SH+ Replace Token-2"
SHA_DEL_ALL_CKS_REQ = "SH+ Delete All Cookies in Request"

CHECK_EXT_SCRIPT_DO_NOT_WAIT = False
CHECK_EXT_SCRIPT_EXEC_ON_CLICK = False
DAEMON_MODE = False
ICS_1_CMD = "python3"
ICS_2_CMD = "cmd.exe"
ICS_3_CMD = "powershell.exe"
ICS_1_SCRIPT = "E:\\Burp\\Headless Login\\GoogleSearch.py"
ICS_2_SCRIPT = "/C"
ICS_3_SCRIPT = "-file"
ICS_1_ARGS = "burp"
ICS_2_ARGS = "E:\\Burp\\Headless Login\\wrapper_burp.bat"
ICS_3_ARGS = "E:\\Burp\\Headless Login\\wrapper_PS.ps1"
SHOW_SCRIPT_OUTPUT = False
MAX_THREADS_PER_SHA = 5
THREAD_POOL_1 = 0
THREAD_POOL_2 = 0
THREAD_POOL_3 = 0
THREAD_POOL_LIST_1 = []
THREAD_POOL_LIST_2 = []
THREAD_POOL_LIST_3 = []

class Cookie(ICookie):
    
    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration



class DeleteLocalhostCookies(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()
    
    def getActionName(self):
        global SHA_DEL_LCH_CKS
        return SHA_DEL_LCH_CKS
    
    def performAction(self, current_request, macro_items):
        global SHA_DEL_LCH_CKS, VAL_COOKIE_DOMAIN
        CH1 = CookieHandler(self.callbacks)
        cookieCount = CH1.deleteCookies1("LOCALHOST",VAL_COOKIE_DOMAIN)
        print("[{}] SHA_INVOKED: '{}' - ['{} {}' COOKIES DELETED FROM BURP COOKIE JAR]".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),SHA_DEL_LCH_CKS,VAL_COOKIE_DOMAIN,str(cookieCount)))


class DeleteAllCookies(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()

    def getActionName(self):
        global SHA_DEL_ALL_CKS
        return SHA_DEL_ALL_CKS
    
    def performAction(self, current_request, macro_items):
        global SHA_DEL_ALL_CKS
        CH1 = CookieHandler(self.callbacks)
        cookieCount = CH1.deleteCookies1("ALL")
        print("[{}] SHA_INVOKED: '{}' - ['{}' COOKIES DELETED FROM BURP COOKIE JAR]".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),SHA_DEL_ALL_CKS,str(cookieCount)))          

class ReplaceRefreshToken(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()
              
    def getActionName(self):
        global SHA_MOD_REF_TKN
        return SHA_MOD_REF_TKN
    
    def performAction(self, current_request, macro_items):
        global SHA_MOD_REF_TKN, CHECK_TOKEN2_HEADER, CHECK_TOKEN2_BODY
        if CHECK_TOKEN2_HEADER is False and CHECK_TOKEN2_BODY is False:
            print("[{}] OPERATION TERMINATED: '{}' invoked but Header & Body in 3B are un-checked.".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),SHA_MOD_REF_TKN))
            return

        global VAL_TOKEN2_BODY_PARAM_NAME_1, VAL_REFRESH_TOKEN_COOKIE_NAME, VAL_COOKIE_DOMAIN, VAL_TOKEN2_BODY_PARAM_NAME_2,VAL_TOKEN2_HDR_PARAM_NAME_1,CHECK_TOKEN2_HEADER_ADD_IF_NOT_EXIST, REPLACE_STRUCTURE_TOKEN2_HEAD, REPLACE_STRUCTURE_TOKEN2_BODY

        try:
            requestInfo = self.helpers.analyzeRequest(current_request)
            headers = requestInfo.getHeaders()

            url = self.helpers.analyzeRequest(current_request).getUrl().toString()
            CH2 = CookieHandler(self.callbacks)
            TKN2, reqPath, cookiePath, matchComment, cookieCount = CH2.getCookieValueCustomPath(VAL_COOKIE_DOMAIN, VAL_REFRESH_TOKEN_COOKIE_NAME, url)
            
            if TKN2 != None:
                mods = []
                header_1_match_found_in_req = False
                header_replace = "No header/body found to replace."
                request = current_request.getRequest()
                headers = self.helpers.analyzeRequest(request).getHeaders()
                body = current_request.getRequest()[requestInfo.getBodyOffset():]
                
                for header in headers:
                    if header.lower().startswith(VAL_TOKEN2_HDR_PARAM_NAME_1.lower()):
                        header_1_match_found_in_req = True
                        break

                if header_1_match_found_in_req and CHECK_TOKEN2_HEADER:
                    for i, header in enumerate(headers):
                        if header.lower().startswith(VAL_TOKEN2_HDR_PARAM_NAME_1.lower()):
                            headers[i] = REPLACE_STRUCTURE_TOKEN2_HEAD % (VAL_TOKEN2_HDR_PARAM_NAME_1, TKN2)
                            break
                    mods.append(VAL_TOKEN2_HDR_PARAM_NAME_1)

                elif not header_1_match_found_in_req and CHECK_TOKEN2_HEADER and CHECK_TOKEN2_HEADER_ADD_IF_NOT_EXIST:
                    header_replace = REPLACE_STRUCTURE_TOKEN2_HEAD % (VAL_TOKEN2_HDR_PARAM_NAME_1, TKN2)
                    headers.add(header_replace)
                    mods.append("NEW_" + VAL_TOKEN2_HDR_PARAM_NAME_1)

                if CHECK_TOKEN2_BODY:
                    bodyString = self.helpers.bytesToString(body)
                    if re.search(VAL_TOKEN2_BODY_PARAM_NAME_1, bodyString, re.IGNORECASE):
                        bodyString = re.sub(VAL_TOKEN2_BODY_PARAM_NAME_1, REPLACE_STRUCTURE_TOKEN2_BODY % (VAL_TOKEN2_BODY_PARAM_NAME_2, TKN2), bodyString)
                        body = self.helpers.stringToBytes(bodyString)
                        mods.append("BODY_" + VAL_TOKEN2_BODY_PARAM_NAME_1)
                
                if not mods:
                    print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] - TKN2_OPERATION_TERMINATED: Request doesn't have known token in header/body - [ReqURL:" + url + "]")
                else:
                    message = self.helpers.buildHttpMessage(headers, body)
                    current_request.setRequest(message)
                    print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] MODIFY_REQUEST:" + VAL_REFRESH_TOKEN_COOKIE_NAME + " from BCJ - [BCJ_CNT:" + str(cookieCount) + "] [Match:" + matchComment[:1] + "] [Token(-25):" + TKN2[-25:] + "] [" +  ', '.join(mods) + "] [BCJ-Path:" + cookiePath + "] [ReqURL:" + url + "]")
        except Exception as e:
            print("EXCEPTION OCCURED:\n\t{}".format(e))
        return


class InvokeExternalScript:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

    def invokeScript(self, arg0, arg1, arg2, arg3=None, arg4=None):
        global MAX_THREADS_PER_SHA, THREAD_POOL_1, THREAD_POOL_LIST_1, DAEMON_MODE

        def external_script_popen():
            global THREAD_POOL_1, MAX_THREADS_PER_SHA, SHOW_SCRIPT_OUTPUT, THREAD_POOL_LIST_1,CHECK_EXT_SCRIPT_DO_NOT_WAIT
            thread_pool = threading.current_thread()#.name
            print("[{}] [{}] SCRITP_EXEC_STARTED: [THREADS:{}/{}] '{}': [External script started] [Script Output: {}] ARGS:{}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,THREAD_POOL_1, MAX_THREADS_PER_SHA,arg0, SHOW_SCRIPT_OUTPUT,command))
            self.callbacks.issueAlert("SCRITP_EXEC_STARTED: '{}' Invoked".format(arg0))
            try:
                process  = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if SHOW_SCRIPT_OUTPUT or CHECK_EXT_SCRIPT_DO_NOT_WAIT is False:
                    stdout, stderr = process.communicate()

                if SHOW_SCRIPT_OUTPUT:
                    print("[{}] [{}] SCRITP_EXCE_LOG_START : '{}' >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>[STD_OUT:'{}' - STD_ERR:'{}']".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,arg0,len(stdout),len(stderr)))
                    if len(stdout) > 1:
                        print("[{}] [{}] ------------ OUTPUT ------------\n{}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,stdout.decode()))
                    if len(stderr) > 1:
                        print("[{}] [{}] ------------ ERROR ------------\n{}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,stderr.decode()))
                    print("[{}] [{}] SCRITP_EXCE_LOG_STOP : '{}' <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,arg0))
                print("[{}] [{}] SCRITP_EXEC_COMPLETED: [THREADS:{}/{}] '{}': [External script completed without any exceptions]".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,THREAD_POOL_1, MAX_THREADS_PER_SHA,arg0))
                self.callbacks.issueAlert("SCRITP_EXEC_COMPLETED: '{}' Script execution completed".format(arg0))

            except Exception as e:
                print("[{}] [{}] SCRITP_EXEC_ERROR: [THREADS:{}/{}] '{}': [Error running external script] ARGS:{} [ERR: {}]".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thread_pool,THREAD_POOL_1, MAX_THREADS_PER_SHA,arg0,command,e))
                self.callbacks.issueAlert("SCRITP_EXEC_ERROR: '{}' Error invoking the script.".format(arg0))
            
            THREAD_POOL_1 = THREAD_POOL_1 - 1
            THREAD_POOL_LIST_1.remove(thread_pool)


        if arg3 is None or arg3 == "":
            command = [arg1, arg2]
        else:
            command = [arg1, arg2, arg3]
        
        if THREAD_POOL_1 >= MAX_THREADS_PER_SHA:
            print("[{}] SCRITP_MAX_LIMIT_REACHED: '{}': [External script exec request not entertained. Threads max limit reached] [MAX LIMIT: {}] [ACTIVE THREADS: {}] ARGS:{}\n\t\t ACTIVE THREADS: {}"
                .format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),arg0, MAX_THREADS_PER_SHA,THREAD_POOL_1,command,THREAD_POOL_LIST_1))
            self.callbacks.issueAlert("SCRITP_MAX_LIMIT_REACHED: '{}' Max Limit Reached.".format(arg0))
        else:
            THREAD_POOL_1 = THREAD_POOL_1 + 1
            t = threading.Thread(target=external_script_popen)
            THREAD_POOL_LIST_1.append(t)
            t.daemon = DAEMON_MODE
            t.start()

class InvokeCS1(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()
            
    def getActionName(self):
        global SHA_CS1
        return SHA_CS1
    
    def performAction(self, current_request, macro_items):
        global SHA_CS1, ICS_1_CMD, ICS_1_SCRIPT, ICS_1_ARGS
        IES = InvokeExternalScript(self.callbacks)
        IES.invokeScript(SHA_CS1, ICS_1_CMD, ICS_1_SCRIPT, ICS_1_ARGS)


class InvokeCS2(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()
            
    def getActionName(self):
        global SHA_CS2
        return SHA_CS2
    
    def performAction(self, current_request, macro_items):
        global SHA_CS2, ICS_2_CMD, ICS_2_SCRIPT, ICS_2_ARGS
        IES = InvokeExternalScript(self.callbacks)
        IES.invokeScript(SHA_CS2, ICS_2_CMD, ICS_2_SCRIPT, ICS_2_ARGS)


class InvokeCS3(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()
            
    def getActionName(self):
        global SHA_CS3
        return SHA_CS3
    
    def performAction(self, current_request, macro_items):
        global SHA_CS3, ICS_3_CMD, ICS_3_SCRIPT, ICS_3_ARGS
        IES = InvokeExternalScript(self.callbacks)
        IES.invokeScript(SHA_CS3, ICS_3_CMD, ICS_3_SCRIPT, ICS_3_ARGS)


class ReplaceAccessToken(ISessionHandlingAction):
    def __init__(self, callbacks):
        self.callbacks  = callbacks 
        self.helpers = callbacks.getHelpers()
            
    def getActionName(self):
        global SHA_MOD_JWT_TKN
        return SHA_MOD_JWT_TKN
    
    def performAction(self, current_request, macro_items):
        global CHECK_TOKEN1_HEADER_1, CHECK_TOKEN1_HEADER_2, CHECK_TOKEN1_BODY
        if CHECK_TOKEN1_HEADER_1 is False and CHECK_TOKEN1_HEADER_2 is False and CHECK_TOKEN1_BODY is False:
            print("[{}] OPERATION TERMINATED: '{}' invoked but Header-1, Header-2 & Body-1 in 3A are un-checked.".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),SHA_MOD_JWT_TKN))
            return

        
        global VAL_JWT_COOKIE_NAME, VAL_REFRESH_TOKEN_COOKIE_NAME, VAL_COOKIE_DOMAIN, VAL_JWT_HEADER_NAME_1, VAL_JWT_HEADER_NAME_2, CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_1, CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_2,SHA_MOD_JWT_TKN,VAL_JWT_BODY_NAME_1,VAL_JWT_BODY_NAME_2, REPLACE_STRUCTURE_TOKEN1_HEAD_1, REPLACE_STRUCTURE_TOKEN1_HEAD_2, REPLACE_STRUCTURE_TOKEN1_BODY
        try:
            requestInfo = self.helpers.analyzeRequest(current_request)
            headers = requestInfo.getHeaders()
            url = self.helpers.analyzeRequest(current_request).getUrl().toString()
            CH1 = CookieHandler(self.callbacks)
            jwt, reqPath, cookiePath, matchComment, cookieCount = CH1.getCookieValueCustomPath(VAL_COOKIE_DOMAIN, VAL_JWT_COOKIE_NAME, url)
            if jwt != None:
                mods = []
                header_selected = "NONE"
                header_1_match_found_in_req = False
                header_2_match_found_in_req = False
                request = current_request.getRequest()
                headers = self.helpers.analyzeRequest(request).getHeaders()
                body = current_request.getRequest()[requestInfo.getBodyOffset():]
                for header in headers:
                    if header.lower().startswith(VAL_JWT_HEADER_NAME_1.lower()):
                        header_1_match_found_in_req = True
                    if header.lower().startswith(VAL_JWT_HEADER_NAME_2.lower()):
                        header_2_match_found_in_req = True
                if header_1_match_found_in_req and CHECK_TOKEN1_HEADER_1:
                    for i, header in enumerate(headers):
                        if header.lower().startswith(VAL_JWT_HEADER_NAME_1.lower()):
                            headers[i] = REPLACE_STRUCTURE_TOKEN1_HEAD_1 % (VAL_JWT_HEADER_NAME_1, jwt)
                            break    
                    mods.append(VAL_JWT_HEADER_NAME_1)
                elif not header_1_match_found_in_req and CHECK_TOKEN1_HEADER_1 and CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_1:
                    header_replace = REPLACE_STRUCTURE_TOKEN1_HEAD_1 % (VAL_JWT_HEADER_NAME_1, jwt)
                    headers.add(header_replace)
                    mods.append("NEW_" + VAL_JWT_HEADER_NAME_1)
                if header_2_match_found_in_req and CHECK_TOKEN1_HEADER_2:
                    for i, header in enumerate(headers):
                        if header.lower().startswith(VAL_JWT_HEADER_NAME_2.lower()):
                            headers[i] = REPLACE_STRUCTURE_TOKEN1_HEAD_2 % (VAL_JWT_HEADER_NAME_2, jwt)
                            break    
                    mods.append(VAL_JWT_HEADER_NAME_2)
                elif not header_2_match_found_in_req and CHECK_TOKEN1_HEADER_2 and CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_2:
                    header_replace = REPLACE_STRUCTURE_TOKEN1_HEAD_2 % (VAL_JWT_HEADER_NAME_2, jwt)
                    headers.add(header_replace)
                    mods.append("NEW_" + VAL_JWT_HEADER_NAME_2)
                if CHECK_TOKEN1_BODY:
                    bodyString = self.helpers.bytesToString(body)
                    if re.search(VAL_JWT_BODY_NAME_1, bodyString, re.IGNORECASE):
                        bodyString = re.sub(VAL_JWT_BODY_NAME_1, REPLACE_STRUCTURE_TOKEN1_BODY % (VAL_JWT_BODY_NAME_2, jwt), bodyString)
                        body = self.helpers.stringToBytes(bodyString)
                        mods.append("BODY_" + VAL_JWT_BODY_NAME_1)
                if not mods:
                    print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] - TKN1_OPERATION_TERMINATED: Request doesn't have known token in header/body - [ReqURL:" + url + "]")
                else:
                    message = self.helpers.buildHttpMessage(headers, body)
                    current_request.setRequest(message)
                    print("[" + datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S") + "] MODIFY_REQUEST:" + VAL_JWT_COOKIE_NAME + " from BCJ - [BCJ_CNT:" + str(cookieCount) + "] [Match:" + matchComment[:1] + "] [Token(-25):" + jwt[-25:] + "] [" +  ', '.join(mods) + "] [BCJ-Path:" + cookiePath + "] [ReqURL:" + url + "]")
        except Exception as e:
            print("EXCEPTION OCCURED:\n\t{}".format(e))
        return
                


class CookieHandler:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

    def deleteCookies1(self, arg1, arg2=None):
        cookies = self.callbacks.getCookieJarContents()
        cookieCount = 0
        
        if arg1 == "LOCALHOST":
            for cookie in cookies:
                if cookie.getDomain() == arg2:
                    cookie_to_delete = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
                    self.callbacks.updateCookieJar(cookie_to_delete)
                    cookieCount = cookieCount + 1
            return cookieCount
        elif arg1 == "ALL":
            for cookie in cookies:
                cookie_to_delete = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_delete)
                cookieCount = cookieCount + 1
            return cookieCount
            
            
    def getCookieValue(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                return cookie.getValue()

    def getCookieValueCustomPath(self, domain, name, url):
        cookies = self.callbacks.getCookieJarContents()
        url = url.lower()
        third_slash = url.find('/', url.find('/', url.find('/') + 1) + 1)
        last_slash = url.rfind('/')
        path = url[third_slash:last_slash+1]
        reqURL = url[third_slash:]
        cookieCount = 0
        A = C = D = ''
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookieCount = cookieCount + 1
                A = cookie.getValue()
                C = cookie.getPath()
                D = "1.One Entry Exist"
        if cookieCount == 1:
             return A, path, C, D, cookieCount
        elif cookieCount == 0:
            return None, None, None, "0.No cookies found", cookieCount
        
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and str(cookie.getPath()).lower() == path:
                return cookie.getValue(), path, str(cookie.getPath()), "2.Exact match", cookieCount
        
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and (str(cookie.getPath()).lower().find(path)>-1):
                return cookie.getValue(), path, str(cookie.getPath()), "3.Find with /", cookieCount

        path = url[third_slash:last_slash]
        if path == '':
            path = '/'
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and (str(cookie.getPath()).lower().find(path)>-1):
                return cookie.getValue(), path, str(cookie.getPath()), "4.Find without /", cookieCount

        last_but_second_slash = url.rfind('/', 0, url.rfind('/'))
        path = url[third_slash:last_but_second_slash+1]
        if path == '':
            path = '/'
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and (str(cookie.getPath()).lower().find(path)>-1):
                return cookie.getValue(), path, str(cookie.getPath()), "5.Find with /2", cookieCount


        path = url[third_slash:last_but_second_slash]
        if path == '':
            path = '/'
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and (str(cookie.getPath()).lower().find(path)>-1):
                return cookie.getValue(), path, str(cookie.getPath()), "6.Find without /2", cookieCount

        path = '/'
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and str(cookie.getPath()) == path:
                return cookie.getValue(), path, str(cookie.getPath()), "7.Exact match with /", cookieCount
        
        return None, None, None, None, None


class MyHttpListener(IHttpListener):

    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        
    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if messageIsRequest:
            return

        global LISTEN_4_ACCESS_TOKEN, LISTEN_4_REFRESH_TOKEN, CHECK_REQ_URL_REGEX, VALUE_REQ_URL_REGEX, CHECK_PRINT_REJECT_LOGS_1A_1B

        if LISTEN_4_ACCESS_TOKEN is False and LISTEN_4_REFRESH_TOKEN is False:
            print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] - TOKEN_READ_DISABLED: Both listeners 1D & 1E are unchecked. Not validating the request. Quitting processHttpMessage. - [Tool:" + str(toolFlag) + "]")
            return
        
        url = self.helpers.analyzeRequest(currentMessage).getUrl().toString()
        if CHECK_REQ_URL_REGEX:
            matches = re.search(VALUE_REQ_URL_REGEX, url)
            if not matches:
                if CHECK_PRINT_REJECT_LOGS_1A_1B:
                    print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] - REQ_URL_MATCH_FAILED: 1A.URL MATCH FAILED for RegEx '" + VALUE_REQ_URL_REGEX + "'  - [Tool:" + str(toolFlag) + "] [URL:" + url + "]")
                return
            

        global CHECK_RESP_CONTENT_TYPE, VALUE_READ_JWT_REGEX, VALUE_READ_REFRESH_TOKEN_REGEX,  VALUE_REQ_PATH_HEADER, VALUE_RESP_CONTENT_TYPE_HEADER, VAL_COOKIE_DOMAIN, VAL_JWT_COOKIE_NAME, VAL_REFRESH_TOKEN_COOKIE_NAME
        response = self.helpers.analyzeResponse(currentMessage.getResponse())
        headers = response.getHeaders()
        is_it_json = None
        third_slash = url.find('/', url.find('/', url.find('/') + 1) + 1)
        reqURL = url[third_slash:]
        
        if CHECK_RESP_CONTENT_TYPE:
            for header in headers:
                if VALUE_RESP_CONTENT_TYPE_HEADER in header:
                    is_it_json = True
                    break      
            if not is_it_json:       
                if CHECK_PRINT_REJECT_LOGS_1A_1B:
                    print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] - RESP_HEADER_MATCH_FAILED: 1B.Response header match failed for '" + VALUE_RESP_CONTENT_TYPE_HEADER + "'  - [Tool:" + str(toolFlag) + "] [URL:" + url + "]")
                return

        body = currentMessage.getResponse()[response.getBodyOffset():].tostring()
        access_token = None
        refresh_token = None

        if LISTEN_4_ACCESS_TOKEN:
            matches = re.search(VALUE_READ_JWT_REGEX, body)
            if matches:
                access_token = matches.group(1)

        if LISTEN_4_REFRESH_TOKEN:
            matches = re.search(VALUE_READ_REFRESH_TOKEN_REGEX, body)
            if matches:
                refresh_token = matches.group(1)

        if access_token or refresh_token:

            path = "/"
            path_exist_in_req = False

            if CHECK_REQ_PATH:
                request = currentMessage.getRequest()
                request_headers = self.helpers.bytesToString(request).split('\r\n')
                for req_header in request_headers:
                    temp = re.search(VALUE_REQ_PATH_HEADER, req_header, re.IGNORECASE)
                    if temp:
                        path_exist_in_req = True
                        path = temp.group(1).strip()
                        if LISTEN_4_ACCESS_TOKEN and access_token:
                            self._update_cookie_jar(VAL_COOKIE_DOMAIN, VAL_JWT_COOKIE_NAME, access_token,  path, reqURL, toolFlag)
                        if LISTEN_4_REFRESH_TOKEN and refresh_token:
                            self._update_cookie_jar(VAL_COOKIE_DOMAIN, VAL_REFRESH_TOKEN_COOKIE_NAME, refresh_token,  path, reqURL, toolFlag)
                if not path_exist_in_req:
                    if LISTEN_4_ACCESS_TOKEN and access_token:
                        self._update_cookie_jar(VAL_COOKIE_DOMAIN, VAL_JWT_COOKIE_NAME, access_token,  path, reqURL, toolFlag)
                    if LISTEN_4_REFRESH_TOKEN and refresh_token:
                        self._update_cookie_jar(VAL_COOKIE_DOMAIN, VAL_REFRESH_TOKEN_COOKIE_NAME, refresh_token,  path, reqURL, toolFlag)

            else:          
                if LISTEN_4_ACCESS_TOKEN and access_token:
                    self._update_cookie_jar(VAL_COOKIE_DOMAIN, VAL_JWT_COOKIE_NAME, access_token,  path, reqURL, toolFlag)
                if LISTEN_4_REFRESH_TOKEN and refresh_token:
                     self._update_cookie_jar(VAL_COOKIE_DOMAIN, VAL_REFRESH_TOKEN_COOKIE_NAME, refresh_token,  path, reqURL, toolFlag)

        return

    def _update_cookie_jar(self, domainName, cookieName, cookieValue, path, ReqURL, toolFlag):
        cookie = Cookie(domainName, cookieName, cookieValue,  path, None)
        self.callbacks.updateCookieJar(cookie)
        print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] + READ_RESPONSE:" + cookieName + " - [Tool:" + str(toolFlag) + "] [Token(-40):" + cookieValue[-30:] + "] [BCJ-Path:" + path+ "] [ReqURL:" + ReqURL + "]")
    
    def toggleHttpListener(self, event):
        if event.getSource().isSelected():
            self.callbacks.registerHttpListener(self)
            print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] + REGISTER ACTION:  registerHttpListener. Tokens will be read from response.")
        else:
            self.callbacks.removeHttpListener(self)
            print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] - UNREGISTER ACTION:  removeHttpListener. Tokens will not be read from response.")

class MyTab(ITab,IExtensionStateListener):
    def __init__(self, callbacks, httpListener):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self._httpListener = httpListener
        self.process = None

        self._mainPanel = JPanel()
        self._mainPanel.setLayout(BoxLayout(self._mainPanel, BoxLayout.Y_AXIS))
        self._docReferencePanel = JPanel(GridLayout(0, 1, 5, 5))
        self._docReferencePanel.setBorder(BorderFactory.createTitledBorder("About 'Session Handler Plus {}'".format(EXT_VERSION)))
        self._mainPanel.add(self._docReferencePanel)
        
        class ClickListener(MouseAdapter):
            def __init__(self, uri):
                self.uri = uri
                
            def mouseClicked(self, event):
                Desktop.getDesktop().browse(self.uri)

        self._refLable = JLabel("{}".format(VAL_ABOUT_SHP_MINI))
        self._refLable.setCursor(Cursor(Cursor.HAND_CURSOR))
        self._refLable.addMouseListener(ClickListener(URI("{}".format(VAL_REF_LINK))))
        self._refLable.setForeground(Color.BLUE)
        self._docReferencePanel.add(self._refLable)

        self._httpListenerPanel = JPanel()
        self._httpListenerPanel.setLayout(BoxLayout(self._httpListenerPanel, BoxLayout.Y_AXIS))

        self._firstPanel = JPanel(GridLayout(0, 3, 10, 2))
        self._httpListenerPanel.add(self._firstPanel)

        self._httpListenerCheckbox = JCheckBox("Enable HTTP Listener", True)
        self._httpListenerCheckbox.addActionListener(self.toggleHttpListener)
        self._firstPanel.add(self._httpListenerCheckbox)
 
        self._print1A1BLogsCheckbox = JCheckBox("Print failed logs for 1A & 1B (troubleshooting)", False)
        self._print1A1BLogsCheckbox.addActionListener(self.togglePrint1A1BLogs)
        self._print1A1BLogsCheckbox.setEnabled(False)
        self._firstPanel.add(self._print1A1BLogsCheckbox)
 
        self._respHeaderValPane0 = JPanel(GridLayout(0, 3, 5, 7))
        self._httpListenerPanel.add(self._respHeaderValPane0)

        self._respheaderValidation0Checkbox = JCheckBox("1A. Read tokens only if the request URL matches (RegEx)", True)
        self._respheaderValidation0Checkbox.addActionListener(self.toggleReqUrlCheck)
        self._respHeaderValPane0.add(self._respheaderValidation0Checkbox)

        self._respheaderValidation0text_field  = JTextField(10)
        self._respheaderValidation0text_field.setText(VALUE_REQ_URL_REGEX)
        self._respHeaderValPane0.add(self._respheaderValidation0text_field)

        self._respheaderValidation0Button1  = JButton("Set Request URL RegEx match", actionPerformed=self.reqUrlValidationButtonClicked)
        self._respHeaderValPane0.add(self._respheaderValidation0Button1)
        
        self._respHeaderValPanel = JPanel(GridLayout(0, 3, 5, 7))
        self._httpListenerPanel.add(self._respHeaderValPanel)

        self._respheaderValidationCheckbox = JCheckBox("1B. Read tokens only if Response header contain ", True)
        self._respheaderValidationCheckbox.addActionListener(self.toggleRespHeaderCheck)
        self._respHeaderValPanel.add(self._respheaderValidationCheckbox)
        
        self._respheaderValidationtext_field  = JTextField(10)
        self._respheaderValidationtext_field.setText(VALUE_RESP_CONTENT_TYPE_HEADER)
        self._respHeaderValPanel.add(self._respheaderValidationtext_field)

        self._respheaderValidationButton1  = JButton("Set Response Validation Header", actionPerformed=self.respheaderValidationButtonClicked)
        self._respHeaderValPanel.add(self._respheaderValidationButton1)
        
        self._reqHeaderPathPanel = JPanel(GridLayout(0, 3, 5, 7))
        self._httpListenerPanel.add(self._reqHeaderPathPanel)

        self._reqHeaderPathCheckbox = JCheckBox("1C. Look for Path request header(s) and add to BCJ ", True)
        self._reqHeaderPathCheckbox.addActionListener(self.toggleReqPathHeaderCheck)
        self._reqHeaderPathPanel.add(self._reqHeaderPathCheckbox)
        
        self._reqHeaderPathtext_field  = JTextField(10)
        self._reqHeaderPathtext_field.setText(VALUE_REQ_PATH_HEADER)
        self._reqHeaderPathPanel.add(self._reqHeaderPathtext_field)


        self._reqHeaderPathButton1  = JButton("Set Path Header", actionPerformed=self.reqHeaderPathButtonClicked)
        self._reqHeaderPathPanel.add(self._reqHeaderPathButton1)
        

        self._accessTokenPanel = JPanel(GridLayout(0, 3, 5, 7))
        self._httpListenerPanel.add(self._accessTokenPanel)
        
        self._accessTokenListenerCheckbox = JCheckBox("1D. Look for TOKEN-1 in the response body (Ex: JWT)", True)
        self._accessTokenListenerCheckbox.addActionListener(self.toggleAccessToken)
        self._accessTokenPanel.add(self._accessTokenListenerCheckbox)

        self._accessTokentext_field  = JTextField(20)
        self._accessTokentext_field.setText(VALUE_READ_JWT_REGEX)
        self._accessTokenPanel.add(self._accessTokentext_field)

        self._accessTokenButton1  = JButton("Set TOKEN-1 RegEx", actionPerformed=self.accessTokenButtonClicked)
        self._accessTokenPanel.add(self._accessTokenButton1)
 
        self._refreshTokenPanel = JPanel(GridLayout(0, 3, 5, 7))
        self._httpListenerPanel.add(self._refreshTokenPanel)
        self._refreshTokenListenerCheckbox = JCheckBox("1E. Look for TOKEN-2 in the response body (Ex: Refresh_Token)", True)
        self._refreshTokenListenerCheckbox.addActionListener(self.toggleRefreshToken)
        self._refreshTokenPanel.add(self._refreshTokenListenerCheckbox)
        self._refreshTokentext_field  = JTextField(20)
        self._refreshTokentext_field.setText(VALUE_READ_REFRESH_TOKEN_REGEX)
        self._refreshTokenPanel.add(self._refreshTokentext_field)
        self._refreshTokenButton1  = JButton("Set TOKEN-2 RegEx", actionPerformed=self.refreshTokenButtonClicked)
        self._refreshTokenPanel.add(self._refreshTokenButton1)
        self._mainPanel.add(self._httpListenerPanel)
        self._httpListenerPanel.setBorder(BorderFactory.createTitledBorder("1. Listener - Get JWT/Refresh_Token/CSRF_Token from Response [Invoked By: Auto] [Scope: Proxy, Repeater, Scanner, Intruder etc]"))

        self._statusPanel = JPanel(GridLayout(1, 1))
        self._statusPanel.setBorder(BorderFactory.createTitledBorder("2. STATUS PANEL (Controls generated text in brief)"))
        self._mainPanel.add(self._statusPanel)
        self._statusLable1 = JTextField(100)
        self._statusLable1.setEditable(False)
        self._statusPanel.add(self._statusLable1)
        
        self._settingsPanel = JPanel()
        self._settingsPanel.setLayout(BoxLayout(self._settingsPanel, BoxLayout.Y_AXIS))
        self._settingsPanel.setBorder(BorderFactory.createTitledBorder("3. Modifier - Update the request  [Invoked By: SHA] [Scope: As defined in Session Handling Action]"))
        self._mainPanel.add(self._settingsPanel)
       
        self._modifyAccessTokenValPanel = JPanel()
        self._modifyAccessTokenValPanel.setLayout(BoxLayout(self._modifyAccessTokenValPanel, BoxLayout.Y_AXIS))
        self._modifyAccessTokenValPanel.setBorder(BorderFactory.createTitledBorder("3A. Modify Token-1 in Request (Header/Body) (Ex: JWT)"))
        self._settingsPanel.add(self._modifyAccessTokenValPanel)

        self._sessionhandlingRules3APanel = JPanel(GridLayout(0, 1, 10, 2))
        self._modifyAccessTokenValPanel.add(self._sessionhandlingRules3APanel)

        self._replaceAccessTokenCheckbox = JCheckBox("Enable '{}'. Token-1 with relavent path will be used in all the positions below".format(SHA_MOD_JWT_TKN), False)
        self._replaceAccessTokenCheckbox.addActionListener(self.toggleSHA_ReplaceAccessToken)
        self._sessionhandlingRules3APanel.add(self._replaceAccessTokenCheckbox)
        
        self._sessionhandlingRules3A2Panel = JPanel(GridLayout(0, 5, 10, 2))
        self._modifyAccessTokenValPanel.add(self._sessionhandlingRules3A2Panel)

        self._updateJWT1ValidationCheckbox = JCheckBox("Update Header 1 (for Token-1)", True)
        self._updateJWT1ValidationCheckbox.addActionListener(self.toggleModifyJWT1Check)
        self._updateJWT1ValidationCheckbox.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT1ValidationCheckbox)
        
        self._updateJWT1Validationtext_field  = JTextField(10)
        self._updateJWT1Validationtext_field.setText(VAL_JWT_HEADER_NAME_1)
        self._updateJWT1Validationtext_field.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT1Validationtext_field)
 
        self._updateJWT1ReplaceStringText_field  = JTextField(4)
        self._updateJWT1ReplaceStringText_field.setText(REPLACE_STRUCTURE_TOKEN1_HEAD_1)
        self._updateJWT1ReplaceStringText_field.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT1ReplaceStringText_field)
 
        self._updateJWT1ValidationButton1  = JButton("Set Token-1 Header-1", actionPerformed=self.ModifyJWT1ButtonClicked)
        self._updateJWT1ValidationButton1.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT1ValidationButton1)
        
        self._addIfNotExist_JWT1ValidationCheckbox = JCheckBox("Add header if not exist", False)
        self._addIfNotExist_JWT1ValidationCheckbox.addActionListener(self.toggleModifyOrAddJWT1Check)
        self._addIfNotExist_JWT1ValidationCheckbox.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._addIfNotExist_JWT1ValidationCheckbox)

        self._updateJWT2ValidationCheckbox = JCheckBox("Update Header 2 (for Token-1)", False)
        self._updateJWT2ValidationCheckbox.addActionListener(self.toggleModifyJWT2Check)
        self._updateJWT2ValidationCheckbox.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT2ValidationCheckbox)
        
        self._updateJWT2Validationtext_field  = JTextField(10)
        self._updateJWT2Validationtext_field.setText(VAL_JWT_HEADER_NAME_2)
        self._updateJWT2Validationtext_field.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT2Validationtext_field)
 
        self._updateJWT1ReplaceString2Text_field  = JTextField(4)
        self._updateJWT1ReplaceString2Text_field.setText(REPLACE_STRUCTURE_TOKEN1_HEAD_2)
        self._updateJWT1ReplaceString2Text_field.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT1ReplaceString2Text_field)
  
        self._updateJWT2ValidationButton1  = JButton("Set Token-1 Header-2", actionPerformed=self.ModifyJWT2ButtonClicked)
        self._updateJWT2ValidationButton1.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT2ValidationButton1)
        
        self._addIfNotExist_JWT2ValidationCheckbox = JCheckBox("Add header if not exist", False)
        self._addIfNotExist_JWT2ValidationCheckbox.setEnabled(False)
        self._addIfNotExist_JWT2ValidationCheckbox.addActionListener(self.toggleModifyOrAddJWT2Check)
        self._sessionhandlingRules3A2Panel.add(self._addIfNotExist_JWT2ValidationCheckbox)

        self._updateJWT3ValidationCheckbox = JCheckBox("Update Custom Body Parameter", False)
        self._updateJWT3ValidationCheckbox.addActionListener(self.toggleModifyJWT3Check)
        self._updateJWT3ValidationCheckbox.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT3ValidationCheckbox)
        
        self._updateJWT3Validationtext_field  = JTextField(10)
        self._updateJWT3Validationtext_field.setText(VAL_JWT_BODY_NAME_1)
        self._updateJWT3Validationtext_field.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT3Validationtext_field)
        
        self._updateJWT3Validationtext_field2  = JTextField(10)
        self._updateJWT3Validationtext_field2.setText(VAL_JWT_BODY_NAME_2)
        self._updateJWT3Validationtext_field2.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT3Validationtext_field2)
 
        self._updateJWT1ReplaceString3Text_field  = JTextField(4)
        self._updateJWT1ReplaceString3Text_field.setText(REPLACE_STRUCTURE_TOKEN1_BODY)
        self._updateJWT1ReplaceString3Text_field.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT1ReplaceString3Text_field)
   
        self._updateJWT3ValidationButton1  = JButton("Set body parameter", actionPerformed=self.ModifyJWT3ButtonClicked)
        self._updateJWT3ValidationButton1.setEnabled(False)
        self._sessionhandlingRules3A2Panel.add(self._updateJWT3ValidationButton1)
 
        self._modifyRefreshTokenValPanel = JPanel()
        self._modifyRefreshTokenValPanel.setLayout(BoxLayout(self._modifyRefreshTokenValPanel, BoxLayout.Y_AXIS))
        self._modifyRefreshTokenValPanel.setBorder(BorderFactory.createTitledBorder("3B. Modify Token-2 in Request (Header/Body) (Ex: Refresh_Token/CSRF_Token)"))
        self._settingsPanel.add(self._modifyRefreshTokenValPanel)

        self._modifyRefreshTokenValPanel1A = JPanel(GridLayout(0, 1, 10, 2))
        self._modifyRefreshTokenValPanel.add(self._modifyRefreshTokenValPanel1A)
        self._replaceRefreshTokenCheckbox = JCheckBox("Enable '{}'. Token-2 with relavent path will be used in both the positions below".format(SHA_MOD_REF_TKN), False)
        self._replaceRefreshTokenCheckbox.addActionListener(self.toggleSHA_ReplaceRefreshToken)
        self._modifyRefreshTokenValPanel1A.add(self._replaceRefreshTokenCheckbox)
        self._modifyRefreshTokenValPanel1 = JPanel(GridLayout(0, 5, 10, 2))
        self._modifyRefreshTokenValPanel.add(self._modifyRefreshTokenValPanel1)

        self._updateREF1ValidationCheckbox = JCheckBox("Update Token-2 in Request Header", False)
        self._updateREF1ValidationCheckbox.addActionListener(self.toggleModifyTKN2ACheck)
        self._updateREF1ValidationCheckbox.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateREF1ValidationCheckbox)

        self._updateRefTknValidationtext_field  = JTextField()
        self._updateRefTknValidationtext_field.setText(VAL_TOKEN2_HDR_PARAM_NAME_1)
        self._updateRefTknValidationtext_field.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTknValidationtext_field)

        self._updateRefTknString1Text_field  = JTextField(4)
        self._updateRefTknString1Text_field.setText(REPLACE_STRUCTURE_TOKEN2_HEAD)
        self._updateRefTknString1Text_field.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTknString1Text_field)
   
        self._updateRefTknValidationButton1  = JButton("Set Token-2 Header", actionPerformed=self.ModifyRefTkn21ButtonClicked)
        self._updateRefTknValidationButton1.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTknValidationButton1)
        
        self._addIfNotExist_RefTknValidationCheckbox = JCheckBox("Add header if not exist", False)
        self._addIfNotExist_RefTknValidationCheckbox.addActionListener(self.toggleModifyOrAddTKN2Check)
        self._addIfNotExist_RefTknValidationCheckbox.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._addIfNotExist_RefTknValidationCheckbox)

        self._updateREF2ValidationCheckbox = JCheckBox("Update Token-2 in Request Body", True)
        self._updateREF2ValidationCheckbox.addActionListener(self.toggleModifyTKN2BCheck)
        self._updateREF2ValidationCheckbox.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateREF2ValidationCheckbox)

        self._updateRefTkn2Validationtext_field  = JTextField()
        self._updateRefTkn2Validationtext_field.setText(VAL_TOKEN2_BODY_PARAM_NAME_1)
        self._updateRefTkn2Validationtext_field.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTkn2Validationtext_field)

        self._updateRefTkn2Validation2text_field  = JTextField()
        self._updateRefTkn2Validation2text_field.setText(VAL_TOKEN2_BODY_PARAM_NAME_2)
        self._updateRefTkn2Validation2text_field.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTkn2Validation2text_field)

        self._updateRefTknString2Text_field  = JTextField(4)
        self._updateRefTknString2Text_field.setText(REPLACE_STRUCTURE_TOKEN2_BODY)
        self._updateRefTknString2Text_field.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTknString2Text_field)
   
        self._updateRefTkn2ValidationButton1  = JButton("Set Token-2 Body", actionPerformed=self.ModifyRefTkn22ButtonClicked)
        self._updateRefTkn2ValidationButton1.setEnabled(False)
        self._modifyRefreshTokenValPanel1.add(self._updateRefTkn2ValidationButton1)

        self._sessionHandlingRulesPanel = JPanel(GridLayout(0, 4, 5, 5))

        self._invokeScript1Checkbox = JCheckBox("5A. Add Rule '{}'".format(SHA_CS1), False)
        self._invokeScript1Checkbox.addActionListener(self.toggleSHA_InvokeCS1)
        self._invokeScript2Checkbox = JCheckBox("5B. Add Rule '{}'".format(SHA_CS2), False)
        self._invokeScript2Checkbox.addActionListener(self.toggleSHA_InvokeCS2)
        self._invokeScript3Checkbox = JCheckBox("5C. Add Rule '{}'".format(SHA_CS3), False)
        self._invokeScript3Checkbox.addActionListener(self.toggleSHA_InvokeCS3)

        self._deleteAllCookiesCheckbox = JCheckBox("Add Rule '{}'".format(SHA_DEL_ALL_CKS), False)
        self._deleteAllCookiesCheckbox.addActionListener(self.toggleSHA_DeleteAllCookiesBCJ)

        self._deleteLocalhostCookiesCheckbox = JCheckBox("Add Rule '{}'".format(SHA_DEL_LCH_CKS), False)
        self._deleteLocalhostCookiesCheckbox.addActionListener(self.toggleSHA_DeleteLocalhostCookiesBCJ)

        self._deleteAllCookiesButton1  = JButton("Delete All Cookies from BCJ", actionPerformed=self.deleteAllCookies_ButtonClicked)
        self._deleteLHCookiesButton1  = JButton("Delete Localhost Cookies from BCJ", actionPerformed=self.deleteLHCookies_ButtonClicked)

        self._emptyLable1 = JLabel()
        self._emptyLable1.setEnabled(False)

        self._sessionHandlingRulesPanel.add(self._deleteLocalhostCookiesCheckbox)
        self._sessionHandlingRulesPanel.add(self._deleteAllCookiesCheckbox)
        self._sessionHandlingRulesPanel.add(self._deleteLHCookiesButton1)
        self._sessionHandlingRulesPanel.add(self._deleteAllCookiesButton1)

        self._mainPanel.add(self._sessionHandlingRulesPanel)
        self._sessionHandlingRulesPanel.setBorder(BorderFactory.createTitledBorder("4. Additional Session Handling Actions [Invoked By: SHA or button_click] [Scope: As defined in Session Handling Action]"))
    
        self._customScriptExecPanel = JPanel()
        self._customScriptExecPanel.setLayout(BoxLayout(self._customScriptExecPanel, BoxLayout.Y_AXIS))
        self._customScriptExecPanel.setBorder(BorderFactory.createTitledBorder("5. Invoke Custom Script  (Launch Python/BatchFile/Powershell scripts) [Invoked By: SHA] [Scope: As defined in Session Handling Action]"))
        self._mainPanel.add(self._customScriptExecPanel)

        self._customScriptExecControlPanel = JPanel(GridLayout(0, 4, 10, 20))
        self._customScriptExecPanel.add(self._customScriptExecControlPanel)
        self._customScriptExecCheckbox2 = JCheckBox("Use below button to invoke the script", False)
        self._customScriptExecCheckbox2.addActionListener(self.toggleInvokeScriptOnButtonActionCheck)
        self._customScriptExecControlPanel.add(self._customScriptExecCheckbox2)
        
        self._customScriptExecCheckbox4 = JCheckBox("Run threads in DAEMON mode", False)
        self._customScriptExecCheckbox4.addActionListener(self.toggleDaemonModeButtonActionCheck)
        self._customScriptExecControlPanel.add(self._customScriptExecCheckbox4)
        
        self._customScriptExecCheckbox3 = JCheckBox("Print script output in extension output", False)
        self._customScriptExecCheckbox3.addActionListener(self.togglePrintScriptOutButtonActionCheck)
        self._customScriptExecControlPanel.add(self._customScriptExecCheckbox3)

        self._customScriptExecCheckbox = JCheckBox("Do not wait for results (Run-and-Forget)", False)
        self._customScriptExecCheckbox.addActionListener(self.toggleExternamScriptCheckDoNotWeight)
        self._customScriptExecControlPanel.add(self._customScriptExecCheckbox)
        
        self._customScript1Panel = JPanel(GridLayout(0, 5, 5, 5))
        self._customScript1Panel.setBorder(BorderFactory.createTitledBorder(""))
        self._customScriptExecPanel.add(self._customScript1Panel)

        self._infoLable1 = JLabel("Enable/Disable SHA")
        self._customScript1Panel.add(self._infoLable1)

        self._infoLable2 = JLabel("Executable")
        self._customScript1Panel.add(self._infoLable2)

        self._infoLable3 = JLabel("Args for the Script")
        self._customScript1Panel.add(self._infoLable3)

        self._infoLable4 = JLabel("Args for the Script")
        self._customScript1Panel.add(self._infoLable4)

        self._infoLable5 = JLabel("Set Command [& Run Script]")
        self._customScript1Panel.add(self._infoLable5)
        
        self._customScriptExecBinary1text_field  = JTextField(5)
        self._customScriptExecBinary2text_field  = JTextField(5)
        self._customScriptExecBinary3text_field  = JTextField(5)
        self._customScriptExecBinary1text_field.setText(ICS_1_CMD)
        self._customScriptExecBinary2text_field.setText(ICS_2_CMD)
        self._customScriptExecBinary3text_field.setText(ICS_3_CMD)
        self._customScriptExecBinary1text_field.setEnabled(False)
        self._customScriptExecBinary2text_field.setEnabled(False)
        self._customScriptExecBinary3text_field.setEnabled(False)
        self._customScriptPath1text_field  = JTextField(5)
        self._customScriptPath2text_field  = JTextField(5)
        self._customScriptPath3text_field  = JTextField(5)
        self._customScriptPath1text_field.setText(ICS_1_SCRIPT)
        self._customScriptPath2text_field.setText(ICS_2_SCRIPT)
        self._customScriptPath3text_field.setText(ICS_3_SCRIPT)
        self._customScriptPath1text_field.setEnabled(False)
        self._customScriptPath2text_field.setEnabled(False)
        self._customScriptPath3text_field.setEnabled(False)
        self._customScriptArgs1text_field  = JTextField(3)
        self._customScriptArgs2text_field  = JTextField(3)
        self._customScriptArgs3text_field  = JTextField(3)
        self._customScriptArgs1text_field.setText(ICS_1_ARGS)
        self._customScriptArgs2text_field.setText(ICS_2_ARGS)
        self._customScriptArgs3text_field.setText(ICS_3_ARGS)
        self._customScriptArgs1text_field.setEnabled(False)
        self._customScriptArgs2text_field.setEnabled(False)
        self._customScriptArgs3text_field.setEnabled(False)
        self._customScript1Button1  = JButton("Set ICS1 Values", actionPerformed=self.ics1_ButtonClicked)
        self._customScript2Button1  = JButton("Set ICS2 Values", actionPerformed=self.ics2_ButtonClicked)
        self._customScript3Button1  = JButton("Set ICS3 Values", actionPerformed=self.ics3_ButtonClicked)
        self._customScript1Button1.setEnabled(False)
        self._customScript2Button1.setEnabled(False)
        self._customScript3Button1.setEnabled(False)
        self._customScript1Panel.add(self._invokeScript1Checkbox)
        self._customScript1Panel.add(self._customScriptExecBinary1text_field)
        self._customScript1Panel.add(self._customScriptPath1text_field)
        self._customScript1Panel.add(self._customScriptArgs1text_field)
        self._customScript1Panel.add(self._customScript1Button1)
        self._customScript1Panel.add(self._invokeScript2Checkbox)
        self._customScript1Panel.add(self._customScriptExecBinary2text_field)
        self._customScript1Panel.add(self._customScriptPath2text_field)
        self._customScript1Panel.add(self._customScriptArgs2text_field)
        self._customScript1Panel.add(self._customScript2Button1)
        self._customScript1Panel.add(self._invokeScript3Checkbox)
        self._customScript1Panel.add(self._customScriptExecBinary3text_field)
        self._customScript1Panel.add(self._customScriptPath3text_field)
        self._customScript1Panel.add(self._customScriptArgs3text_field)
        self._customScript1Panel.add(self._customScript3Button1)

        status = False
        self._httpListenerCheckbox.setSelected(status)
        self._respheaderValidation0Checkbox.setEnabled(status)
        self._respheaderValidation0text_field.setEnabled(status)
        self._respheaderValidation0Button1.setEnabled(status)
        
        self._respheaderValidationCheckbox.setEnabled(status)
        self._respheaderValidationtext_field.setEnabled(status)
        self._respheaderValidationButton1.setEnabled(status)
        
        self._reqHeaderPathCheckbox.setEnabled(status)
        self._reqHeaderPathtext_field.setEnabled(status)
        self._reqHeaderPathButton1.setEnabled(status)
        
        self._accessTokenListenerCheckbox.setEnabled(status)
        self._accessTokentext_field.setEnabled(status)
        self._accessTokenButton1.setEnabled(status)
        
        self._refreshTokenListenerCheckbox.setEnabled(status)
        self._refreshTokentext_field.setEnabled(status)
        self._refreshTokenButton1.setEnabled(status)
        
        
        self._replaceAccessTokenCheckbox.setSelected(status)
        self._updateJWT1ValidationCheckbox.setEnabled(status)
        self._updateJWT1Validationtext_field.setEnabled(status)
        self._updateJWT1ValidationButton1.setEnabled(status)
        self._updateJWT1ReplaceStringText_field.setEnabled(status)
        self._addIfNotExist_JWT1ValidationCheckbox.setEnabled(status)
        self._updateJWT2ValidationCheckbox.setEnabled(status)
        self._updateJWT2Validationtext_field.setEnabled(status)
        self._updateJWT1ReplaceString2Text_field.setEnabled(status)
        self._updateJWT2ValidationButton1.setEnabled(status)
        self._addIfNotExist_JWT2ValidationCheckbox.setEnabled(status)
        self._updateJWT3ValidationCheckbox.setEnabled(status)
        self._updateJWT3Validationtext_field.setEnabled(status)
        self._updateJWT3Validationtext_field2.setEnabled(status)
        self._updateJWT1ReplaceString3Text_field.setEnabled(status)
        self._updateJWT3ValidationButton1.setEnabled(status)
        self._statusLable1.setText("THIS IS JUST FOR KNOWING ACTIONS AND BRIEF INFO ON HOW THAT ACTION EFFECTS")

    def addToPanel(self, pane, component, row, column, width, height, anchor):
        constraints = GridBagConstraints()
        constraints.gridx = column
        constraints.gridy = row
        constraints.gridwidth = width
        constraints.gridheight = height
        constraints.anchor = anchor
        constraints.insets = Insets(5,5,5,5)
        if pane == "_mainPanel":
            self._mainPanel.add(component, constraints)
        elif pane == "_httpListenerPanel":
            self._httpListenerPanel.add(component, constraints)
        elif pane == "_accessTokenPanel":
            self._accessTokenPanel.add(component, constraints)
        elif pane == "_refreshTokenPanel":
            self._refreshTokenPanel.add(component, constraints)
        elif pane == "_settingsPanel":
            self._settingsPanel.add(component, constraints)

    def toggleHttpListener(self, event):
        self._httpListener.toggleHttpListener(event)
        status = event.getSource().isSelected()
        self._print1A1BLogsCheckbox.setEnabled(status)
        self._respheaderValidation0Checkbox.setEnabled(status)
        if self._respheaderValidation0Checkbox.isSelected():
            self._respheaderValidation0text_field.setEnabled(status)
            self._respheaderValidation0Button1.setEnabled(status)
        self._respheaderValidationCheckbox.setEnabled(status)
        if self._respheaderValidationCheckbox.isSelected():
            self._respheaderValidationtext_field.setEnabled(status)
            self._respheaderValidationButton1.setEnabled(status)
        self._reqHeaderPathCheckbox.setEnabled(status)
        if self._reqHeaderPathCheckbox.isSelected():
            self._reqHeaderPathtext_field.setEnabled(status)
            self._reqHeaderPathButton1.setEnabled(status)
        self._accessTokenListenerCheckbox.setEnabled(status)
        if self._accessTokenListenerCheckbox.isSelected():
            self._accessTokentext_field.setEnabled(status)
            self._accessTokenButton1.setEnabled(status)
        self._refreshTokenListenerCheckbox.setEnabled(status)
        if self._refreshTokenListenerCheckbox.isSelected():
            self._refreshTokentext_field.setEnabled(status)
            self._refreshTokenButton1.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 1.HTTPListener Enabled. HTTP Responses from various burp tools will be searched for tokens (+)")
        else:
            self._statusLable1.setText("        (-) Update: 1.HTTPListener Disabled. HTTP Responses won't be searched for tokens (-)")

    def togglePrint1A1BLogs(self, event):
        global CHECK_PRINT_REJECT_LOGS_1A_1B
        status = event.getSource().isSelected()
        CHECK_PRINT_REJECT_LOGS_1A_1B = status
        if status:
            self._statusLable1.setText("        (+) Update: 1(2). Logs related to '1A.URL mismatched' and/or '1B.Resp Header match failed' will be printed in Extension output (+)")
        else:
            self._statusLable1.setText("        (-) Update: 1(2). Logs related to '1A.URL mismatched' and/or '1B.Resp Header match failed' will not be printed in Extension output  (-)")

    def toggleReqUrlCheck(self, event):
        global CHECK_REQ_URL_REGEX, VALUE_REQ_URL_REGEX
        status = event.getSource().isSelected()
        CHECK_REQ_URL_REGEX = status
        self._respheaderValidation0text_field.setEnabled(status)
        self._respheaderValidation0Button1.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 1A. URL matched with RegEx '{}' will be searched for tokens (+)".format(VALUE_REQ_URL_REGEX))
        else:
            self._statusLable1.setText("        (-) Update: 1A. All URL's will be searched for tokens (-)")


    def reqUrlValidationButtonClicked(self, event):
        global VALUE_REQ_URL_REGEX
        VALUE_REQ_URL_REGEX = self._respheaderValidation0text_field.getText()
        self._statusLable1.setText("        (+) Update: 1A. URL matched with RegEx '{}' will be searched for tokens (+)".format(VALUE_REQ_URL_REGEX))
   
        
        
    def toggleRespHeaderCheck(self, event):
        global CHECK_RESP_CONTENT_TYPE, VALUE_RESP_CONTENT_TYPE_HEADER
        status = event.getSource().isSelected()
        CHECK_RESP_CONTENT_TYPE = status
        self._respheaderValidationtext_field.setEnabled(status)
        self._respheaderValidationButton1.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 1B. Only the responses with response header '{}' will be searched for tokens (+)".format(VALUE_RESP_CONTENT_TYPE_HEADER))
        else:
            self._statusLable1.setText("        (-) Update: 1B. All responses will be searched for tokens (-)")


    def respheaderValidationButtonClicked(self, event):
        global VALUE_RESP_CONTENT_TYPE_HEADER
        VALUE_RESP_CONTENT_TYPE_HEADER = self._respheaderValidationtext_field.getText()
        self._statusLable1.setText("        (+) Update: 1B. Response with '{}' in response header will be searched for tokens (+)".format(VALUE_RESP_CONTENT_TYPE_HEADER))
           
    def toggleReqPathHeaderCheck(self, event):
        global CHECK_REQ_PATH, VALUE_REQ_PATH_HEADER
        status = event.getSource().isSelected()
        CHECK_REQ_PATH = status
        self._reqHeaderPathtext_field.setEnabled(status)
        self._reqHeaderPathButton1.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 1C. Requests with '{}' request header(s) will be added to cookie jar with different paths but same token (+)".format(VALUE_REQ_PATH_HEADER))
        else:
            self._statusLable1.setText("        (-) Update: 1C. '{}' header validations will not be performed. Token will be stored with 'Path: /' (-)".format(VALUE_REQ_PATH_HEADER))
    def reqHeaderPathButtonClicked(self, event):
        global VALUE_REQ_PATH_HEADER
        VALUE_REQ_PATH_HEADER = self._reqHeaderPathtext_field.getText()
        self._statusLable1.setText("        (+) Update: 1C. Requests with '{}' request header(s) will be added to cookie jar with different paths but same token (+)".format(VALUE_REQ_PATH_HEADER))

    def toggleAccessToken(self, event):
        global LISTEN_4_ACCESS_TOKEN, VALUE_READ_JWT_REGEX
        status = event.getSource().isSelected()
        self._accessTokentext_field.setEnabled(status)
        self._accessTokenButton1.setEnabled(status)
        LISTEN_4_ACCESS_TOKEN = status    
        if status:
            self._statusLable1.setText("        (+) Update: 1D. Token-1 will be fetched from response Body using RegEx '{}' (+)".format(VALUE_READ_JWT_REGEX))
        else:
            self._statusLable1.setText("        (-) Update: 1D. Token-1 will not be fetched from response Body (-)")
            
    def accessTokenButtonClicked(self, event):
        global VALUE_READ_JWT_REGEX
        VALUE_READ_JWT_REGEX = self._accessTokentext_field.getText()
        self._statusLable1.setText("        (+) Update: 1D. Token-1 will be fetched from response Body using RegEx '{}' (+)".format(VALUE_READ_JWT_REGEX))


    def toggleRefreshToken(self, event):
        global LISTEN_4_REFRESH_TOKEN, VALUE_READ_REFRESH_TOKEN_REGEX
        status = event.getSource().isSelected()
        self._refreshTokentext_field.setEnabled(status)
        self._refreshTokenButton1.setEnabled(status)
        LISTEN_4_REFRESH_TOKEN = status
        if status:
            self._statusLable1.setText("        (+) Update: 1E. Token-2 will be fetched from response Body using RegEx '{}' (+)".format(VALUE_READ_REFRESH_TOKEN_REGEX))
        else:
            self._statusLable1.setText("        (-) Update: 1E. Token-2 will not be fetched from response Body (-)")

    def refreshTokenButtonClicked(self, event):
        global VALUE_READ_REFRESH_TOKEN_REGEX
        VALUE_READ_REFRESH_TOKEN_REGEX = self._refreshTokentext_field.getText()
        self._statusLable1.setText("        (+) Update: 1E. Token-2 will be fetched from response Body using RegEx '{}' (+)".format(VALUE_READ_REFRESH_TOKEN_REGEX))
        
    def toggleModifyJWT1Check(self, event):
        global CHECK_TOKEN1_HEADER_1, VAL_JWT_HEADER_NAME_1
        status = event.getSource().isSelected()
        CHECK_TOKEN1_HEADER_1 = status
        self._updateJWT1Validationtext_field.setEnabled(status)
        self._updateJWT1ReplaceStringText_field.setEnabled(status)
        self._updateJWT1ValidationButton1.setEnabled(status)
        self._addIfNotExist_JWT1ValidationCheckbox.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 3A(1). Token-1 in Request Header '{}' will be updated (+)".format(VAL_JWT_HEADER_NAME_1))
        else:
            self._statusLable1.setText("        (-) Update: 3A(1). Token-1 in Request Header '{}' will not be updated (-)".format(VAL_JWT_HEADER_NAME_1))

    def ModifyJWT1ButtonClicked(self, event):
        global VAL_JWT_HEADER_NAME_1, REPLACE_STRUCTURE_TOKEN1_HEAD_1
        VAL_JWT_HEADER_NAME_1 = self._updateJWT1Validationtext_field.getText()
        REPLACE_STRUCTURE_TOKEN1_HEAD_1 = self._updateJWT1ReplaceStringText_field.getText()
        self._statusLable1.setText("        (+) Update: 3A(1). Request Header starts with '{}' will be replaced with '{}' (+)".format(VAL_JWT_HEADER_NAME_1,REPLACE_STRUCTURE_TOKEN1_HEAD_1 % (VAL_JWT_HEADER_NAME_1, "TOKEN-1_from_BurpCookieJar")))


    def toggleModifyOrAddJWT1Check(self, event):
        global CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_1, VAL_JWT_HEADER_NAME_1
        status = event.getSource().isSelected()
        CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_1 = status
        if status:
            self._statusLable1.setText("        (+) Update: 3A(1). If '{}' Header doesn't exist in request, new header will be added with TOKEN-1 (+)".format(VAL_JWT_HEADER_NAME_1))
        else:
            self._statusLable1.setText("        (-) Update: 3A(1). If '{}' Header doesn't exist in request, new header will not be added with TOKEN-1 (-)".format(VAL_JWT_HEADER_NAME_1))
    def toggleModifyJWT2Check(self, event):
        global CHECK_TOKEN1_HEADER_2, VAL_JWT_HEADER_NAME_2
        status = event.getSource().isSelected()
        CHECK_TOKEN1_HEADER_2 = status
        self._updateJWT2Validationtext_field.setEnabled(status)
        self._updateJWT1ReplaceString2Text_field.setEnabled(status)
        self._updateJWT2ValidationButton1.setEnabled(status)
        self._addIfNotExist_JWT2ValidationCheckbox.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 3A(2). Token-1 in Request Header '{}' will be updated (+)".format(VAL_JWT_HEADER_NAME_2))
        else:
            self._statusLable1.setText("        (-) Update: 3A(2). Token-1 in Request Header'{}' will not be updated  (-)".format(VAL_JWT_HEADER_NAME_2))
    def ModifyJWT2ButtonClicked(self, event):
        global VAL_JWT_HEADER_NAME_2, REPLACE_STRUCTURE_TOKEN1_HEAD_2
        VAL_JWT_HEADER_NAME_2 = self._updateJWT2Validationtext_field.getText()
        REPLACE_STRUCTURE_TOKEN1_HEAD_2 = self._updateJWT1ReplaceString2Text_field.getText()
        self._statusLable1.setText("        (+) Update: 3A(2). Request Header starts with '{}' will be replaced with '{}' (+)".format(VAL_JWT_HEADER_NAME_2,REPLACE_STRUCTURE_TOKEN1_HEAD_2 % (VAL_JWT_HEADER_NAME_2, "TOKEN-1_from_BurpCookieJar")))

    def toggleModifyOrAddJWT2Check(self, event):
        global CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_2, VAL_JWT_HEADER_NAME_2
        status = event.getSource().isSelected()
        CHECK_TOKEN1_HEADER_ADD_IF_NOT_EXIST_2 = status
        if status:
            self._statusLable1.setText("        (+) Update: 3A(2). If '{}' Header doesn't exist in request, new header will be added with TOKEN-1 (+)".format(VAL_JWT_HEADER_NAME_2))
        else:
            self._statusLable1.setText("        (-) Update: 3A(2). If '{}' Header doesn't exist in request, new header will not be added with TOKEN-1 (-)".format(VAL_JWT_HEADER_NAME_2))

    def toggleModifyJWT3Check(self, event):
        global CHECK_TOKEN1_BODY,REPLACE_STRUCTURE_TOKEN1_BODY,VAL_JWT_BODY_NAME_1
        status = event.getSource().isSelected()
        CHECK_TOKEN1_BODY = status
        self._updateJWT3Validationtext_field.setEnabled(status)
        self._updateJWT3Validationtext_field2.setEnabled(status)
        self._updateJWT1ReplaceString3Text_field.setEnabled(status)
        self._updateJWT3ValidationButton1.setEnabled(status)
        if status:
            self._statusLable1.setText("       (+) Update: 3A(3). Token-1 in Request Body Parameter '{}' will be updated (+)".format(VAL_JWT_BODY_NAME_1))
        else:
            self._statusLable1.setText("       (-) Update: 3A(3). Token-1 in Request Body Parameter '{}' will not be updated (-)".format(VAL_JWT_BODY_NAME_1))
    def ModifyJWT3ButtonClicked(self, event):
        global VAL_JWT_BODY_NAME_1,VAL_JWT_BODY_NAME_2,REPLACE_STRUCTURE_TOKEN1_BODY
        VAL_JWT_BODY_NAME_1 = self._updateJWT3Validationtext_field.getText()
        VAL_JWT_BODY_NAME_2 = self._updateJWT3Validationtext_field2.getText()
        REPLACE_STRUCTURE_TOKEN1_BODY = self._updateJWT1ReplaceString3Text_field.getText()
        self._statusLable1.setText("        (+) Update: 3A(3). Request body parameter with '{}' will be replaced with '{}' (+)".format(VAL_JWT_BODY_NAME_1, REPLACE_STRUCTURE_TOKEN1_BODY % (VAL_JWT_BODY_NAME_2, "TOKEN-1_from_BurpCookieJar")))

    def toggleModifyOrAddTKN2Check(self, event):
        global CHECK_TOKEN2_HEADER_ADD_IF_NOT_EXIST, CHECK_TOKEN2_HEADER,VAL_TOKEN2_HDR_PARAM_NAME_1
        status = event.getSource().isSelected()
        CHECK_TOKEN2_HEADER_ADD_IF_NOT_EXIST = status
        if status:
            self._statusLable1.setText("        (+) Update: 3B(1). If '{}' Header doesn't exist in request, new header will be added with TOKEN-2 (+)".format(VAL_TOKEN2_HDR_PARAM_NAME_1))
        else:
            self._statusLable1.setText("        (-) Update: 3B(1). If '{}' Header doesn't exist in request, new header will not be added with TOKEN-2 (-)".format(VAL_TOKEN2_HDR_PARAM_NAME_1))

    def toggleModifyTKN2ACheck(self, event):
        global CHECK_TOKEN2_HEADER,VAL_TOKEN2_HDR_PARAM_NAME_1
        status = event.getSource().isSelected()
        CHECK_TOKEN2_HEADER = status
        self._updateRefTknValidationtext_field.setEnabled(status)
        self._updateRefTknValidationButton1.setEnabled(status)
        self._updateRefTknString1Text_field.setEnabled(status)
        self._addIfNotExist_RefTknValidationCheckbox.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 3B(1). TOKEN-2 in Request Header '{}' will be updated (+)".format(VAL_TOKEN2_HDR_PARAM_NAME_1))
        else:
            self._statusLable1.setText("        (-) Update: 3B(1). TOKEN-2 in Request Header '{}' will not be updated (-)".format(VAL_TOKEN2_HDR_PARAM_NAME_1))

    def ModifyRefTkn21ButtonClicked(self, event):
        global VAL_TOKEN2_HDR_PARAM_NAME_1, REPLACE_STRUCTURE_TOKEN2_HEAD
        VAL_TOKEN2_HDR_PARAM_NAME_1 = self._updateRefTknValidationtext_field.getText()
        REPLACE_STRUCTURE_TOKEN2_HEAD = self._updateRefTknString1Text_field.getText()
        self._statusLable1.setText("        (+) Update: 3B. Request header starts with '{}' will be replaced with '{}' (+)".format(VAL_TOKEN2_HDR_PARAM_NAME_1, REPLACE_STRUCTURE_TOKEN2_HEAD % (VAL_TOKEN2_HDR_PARAM_NAME_1, "TOKEN-2_from_BurpCookieJar")))
        

    def toggleModifyTKN2BCheck(self, event):
        global CHECK_TOKEN2_BODY, VAL_TOKEN2_BODY_PARAM_NAME_1
        status = event.getSource().isSelected()
        CHECK_TOKEN2_BODY = status
        self._updateRefTkn2Validationtext_field.setEnabled(status)
        self._updateRefTkn2Validation2text_field.setEnabled(status)
        self._updateRefTknString2Text_field.setEnabled(status)
        self._updateRefTkn2ValidationButton1.setEnabled(status)
        if status:
            self._statusLable1.setText("        (+) Update: 3B(2). TOKEN-2 in Request Body Parameter '{}' will be updated (+)".format(VAL_TOKEN2_BODY_PARAM_NAME_1))
        else:
            self._statusLable1.setText("        (-) Update: 3B(2). TOKEN-2 in Request Body Parameter '{}' will not be updated (-)".format(VAL_TOKEN2_BODY_PARAM_NAME_1))

    def ModifyRefTkn22ButtonClicked(self, event):
        global VAL_TOKEN2_BODY_PARAM_NAME_1, VAL_TOKEN2_BODY_PARAM_NAME_2, REPLACE_STRUCTURE_TOKEN2_BODY
        VAL_TOKEN2_BODY_PARAM_NAME_1 = self._updateRefTkn2Validationtext_field.getText()
        VAL_TOKEN2_BODY_PARAM_NAME_2 = self._updateRefTkn2Validation2text_field.getText()
        REPLACE_STRUCTURE_TOKEN2_BODY = self._updateRefTknString2Text_field.getText()
        self._statusLable1.setText("        (+) Update: 3B. Request body parameter with '{}' will be replaced with '{}' (+)".format(VAL_TOKEN2_BODY_PARAM_NAME_1, REPLACE_STRUCTURE_TOKEN2_BODY % (VAL_TOKEN2_BODY_PARAM_NAME_2, "TOKEN-2_from_BurpCookieJar")))

        
    def toggleExternamScriptCheckDoNotWeight(self, event):
        global CHECK_EXT_SCRIPT_DO_NOT_WAIT,MAX_THREADS_PER_SHA
        status = event.getSource().isSelected()
        CHECK_EXT_SCRIPT_DO_NOT_WAIT = status
        if status:
            self._statusLable1.setText("        (+) Update: 5(4). Run-and-Forget enabled. Helps to bypass max threading limit of '{}' at a time. Uncheck if script not executed completly/killed early/abrupted (+)".format(MAX_THREADS_PER_SHA))
        else:
            self._statusLable1.setText("        (-) Update: 5(4). Run-and-Forget disabled. Max threading limit enforced. Means only '{}' scripts can be run parallelly. Helps to avoid launching the external scripts too many times parallelly (-)".format(MAX_THREADS_PER_SHA))

    def toggleInvokeScriptOnButtonActionCheck(self, event):
        global CHECK_EXT_SCRIPT_EXEC_ON_CLICK
        status = event.getSource().isSelected()
        CHECK_EXT_SCRIPT_EXEC_ON_CLICK = status
        if status:
            self._customScript1Button1.setText("Set + Exec ICS1 Val")
            self._customScript2Button1.setText("Set + Exec ICS2 Val")
            self._customScript3Button1.setText("Set + Exec ICS3 Val")
            self._statusLable1.setText("        (+) Update: 5(1). Below buttons can be used to set values as well as to execute the script now. Good for troubleshooting. (+)")
        else:
            self._customScript1Button1.setText("Set ICS1 Values")
            self._customScript2Button1.setText("Set ICS2 Values")
            self._customScript3Button1.setText("Set ICS3 Values")
            self._statusLable1.setText("        (-) Update: 5(1). Below buttons can be used to set values only. Script will not be executed. (-)")

    def toggleDaemonModeButtonActionCheck(self, event):
        global DAEMON_MODE
        status = event.getSource().isSelected()
        DAEMON_MODE = status
        self._statusLable1.setText("        (+) Update: 5(3). Set 'Thread.daemon = {}' (+)".format(str(status)))

    def togglePrintScriptOutButtonActionCheck(self, event):
        global SHOW_SCRIPT_OUTPUT
        status = event.getSource().isSelected()
        SHOW_SCRIPT_OUTPUT = status
        self._customScriptExecCheckbox.setEnabled(not status)
        if status:
            self._statusLable1.setText("        (+) Update: 5(3). Output of the script will be displayed in the extension output. Good for troubleshooting. (+)")
        else:
            self._statusLable1.setText("        (-) Update: 5(3). Output of the script will not be displayed in the extension output. (-)")

    def ics1_ButtonClicked(self, event):
        global CHECK_EXT_SCRIPT_EXEC_ON_CLICK, ICS_1_CMD, ICS_1_SCRIPT, ICS_1_ARGS
        ICS_1_CMD = self._customScriptExecBinary1text_field.getText()
        ICS_1_SCRIPT = self._customScriptPath1text_field.getText()
        ICS_1_ARGS = self._customScriptArgs1text_field.getText()
        if CHECK_EXT_SCRIPT_EXEC_ON_CLICK:
            IES = InvokeExternalScript(self.callbacks)
            IES.invokeScript("BTN_EXEC_5A", ICS_1_CMD, ICS_1_SCRIPT, ICS_1_ARGS)
            self._statusLable1.setText("        (A) Update: SHA-5A (ICS1). Command Set to '{} {} {}' and started executing (A)".format(ICS_1_CMD,ICS_1_SCRIPT,ICS_1_ARGS))
        else:
            self._statusLable1.setText("        (+) Update: SHA-5A (ICS1). Command Set to '{} {} {}' (+)".format(ICS_1_CMD,ICS_1_SCRIPT,ICS_1_ARGS))

    def ics2_ButtonClicked(self, event):
        global CHECK_EXT_SCRIPT_EXEC_ON_CLICK, ICS_2_CMD, ICS_2_SCRIPT, ICS_2_ARGS
        ICS_2_CMD = self._customScriptExecBinary2text_field.getText()
        ICS_2_SCRIPT = self._customScriptPath2text_field.getText()
        ICS_2_ARGS = self._customScriptArgs2text_field.getText()
        if CHECK_EXT_SCRIPT_EXEC_ON_CLICK:
            IES = InvokeExternalScript(self.callbacks)
            IES.invokeScript("BTN_EXEC_5B", ICS_2_CMD, ICS_2_SCRIPT, ICS_2_ARGS)
            self._statusLable1.setText("        (A) Update: SHA-5B (ICS2). Command Set to '{} {} {}' and started executing (A)".format(ICS_2_CMD,ICS_2_SCRIPT,ICS_2_ARGS))
        else:
            self._statusLable1.setText("        (+) Update: SHA-5B (ICS2). Command Set to '{} {} {}' (+)".format(ICS_2_CMD,ICS_2_SCRIPT,ICS_2_ARGS))
            
    def ics3_ButtonClicked(self, event):
        global CHECK_EXT_SCRIPT_EXEC_ON_CLICK, ICS_3_CMD, ICS_3_SCRIPT, ICS_3_ARGS
        ICS_3_CMD = self._customScriptExecBinary3text_field.getText()
        ICS_3_SCRIPT = self._customScriptPath3text_field.getText()
        ICS_3_ARGS = self._customScriptArgs3text_field.getText()
        if CHECK_EXT_SCRIPT_EXEC_ON_CLICK:
            IES = InvokeExternalScript(self.callbacks)
            IES.invokeScript("BTN_EXEC_5C", ICS_3_CMD, ICS_3_SCRIPT, ICS_3_ARGS)
            self._statusLable1.setText("        (A) Update: SHA-5C (ICS3). Command Set to '{} {} {}' and started executing (A)".format(ICS_3_CMD,ICS_3_SCRIPT,ICS_3_ARGS))
        else:
            self._statusLable1.setText("        (+) Update: SHA-5C (ICS3). Command Set to '{} {} {}' (+)".format(ICS_3_CMD,ICS_3_SCRIPT,ICS_3_ARGS))

    def toggleSHA_DeleteAllCookiesBCJ(self, event):
        global SHA_DEL_ALL_CKS
        if event.getSource().isSelected():
            self.callbacks.registerSessionHandlingAction(DeleteAllCookies(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-4(2). Session Handling Action '{}' added to Burp Session Handling Rules (+)".format(SHA_DEL_ALL_CKS))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_DEL_ALL_CKS:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-4(2). Session Handling Action '{}' removed from Burp Session Handling Rules (-)".format(SHA_DEL_ALL_CKS))

    def deleteAllCookies_ButtonClicked(self, event):
        CH1 = CookieHandler(self.callbacks)
        cookieCount = CH1.deleteCookies1("ALL")
        print("[{}] BUTTON_CLICKED: ['{}' COOKIES DELETED FROM BURP COOKIE JAR]".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),str(cookieCount)))
        self._statusLable1.setText("        (A) Update: SHA-4(4). ALL '{}' COOKIES DELETED FROM BURP COOKIE JAR (A)".format(cookieCount))

    def deleteLHCookies_ButtonClicked(self, event):
        global VAL_COOKIE_DOMAIN
        CH1 = CookieHandler(self.callbacks)
        cookieCount = CH1.deleteCookies1("LOCALHOST",VAL_COOKIE_DOMAIN)
        print("[{}] BUTTON_CLICKED: ['{}' COOKIES DELETED FROM BURP COOKIE JAR]".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),str(cookieCount)))
        self._statusLable1.setText("        (A) Update: SHA-4(3). '{}' {} COOKIES DELETED FROM BURP COOKIE JAR (A)".format(cookieCount,VAL_COOKIE_DOMAIN))

    def toggleSHA_DeleteLocalhostCookiesBCJ(self, event):
        global SHA_DEL_LCH_CKS
        if event.getSource().isSelected():
            self.callbacks.registerSessionHandlingAction(DeleteLocalhostCookies(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-4(1). Session Handling Action '{}' added to Burp Session Handling Rules (+)".format(SHA_DEL_LCH_CKS))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_DEL_LCH_CKS:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-4(1). Session Handling Action '{}' removed from Burp Session Handling Rules (-)".format(SHA_DEL_LCH_CKS))

    def toggleSHA_InvokeCS1(self, event):
        global SHA_CS1
        status = event.getSource().isSelected()
        self._customScriptExecBinary1text_field.setEnabled(status)
        self._customScriptPath1text_field.setEnabled(status)
        self._customScriptArgs1text_field.setEnabled(status)
        self._customScript1Button1.setEnabled(status)
        if status:
            self.callbacks.registerSessionHandlingAction(InvokeCS1(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-5A. Session Handling Action '{}' added to Burp Session Handling Rules (+)".format(SHA_CS1))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_CS1:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-5A. Session Handling Action '{}' removed from Burp Session Handling Rules (-)".format(SHA_CS1))

    def toggleSHA_InvokeCS2(self, event):
        global SHA_CS2
        status = event.getSource().isSelected()
        self._customScriptExecBinary2text_field.setEnabled(status)
        self._customScriptPath2text_field.setEnabled(status)
        self._customScriptArgs2text_field.setEnabled(status)
        self._customScript2Button1.setEnabled(status)
        if status:
            self.callbacks.registerSessionHandlingAction(InvokeCS2(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-5B. Session Handling Action '{}' added to Burp Session Handling Rules (+)".format(SHA_CS2))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_CS2:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-5B. Session Handling Action '{}' removed from Burp Session Handling Rules (-)".format(SHA_CS2))

    def toggleSHA_InvokeCS3(self, event):
        global SHA_CS3
        status = event.getSource().isSelected()
        self._customScriptExecBinary3text_field.setEnabled(status)
        self._customScriptPath3text_field.setEnabled(status)
        self._customScriptArgs3text_field.setEnabled(status)
        self._customScript3Button1.setEnabled(status)
        if status:
            self.callbacks.registerSessionHandlingAction(InvokeCS3(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-5C. Session Handling Action '{}' added to Burp Session Handling Rules (+)".format(SHA_CS3))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_CS3:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-5C. Session Handling Action '{}' removed from Burp Session Handling Rules (-)".format(SHA_CS3))

    def toggleSHA_ReplaceAccessToken(self, event):
        global SHA_MOD_JWT_TKN
        status = event.getSource().isSelected()
        self._updateJWT1ValidationCheckbox.setEnabled(status)
        if self._updateJWT1ValidationCheckbox.isSelected():
            self._updateJWT1Validationtext_field.setEnabled(status)
            self._updateJWT1ValidationButton1.setEnabled(status)
            self._updateJWT1ReplaceStringText_field.setEnabled(status)
            self._addIfNotExist_JWT1ValidationCheckbox.setEnabled(status)
        self._updateJWT2ValidationCheckbox.setEnabled(status)
        if self._updateJWT2ValidationCheckbox.isSelected():
            self._updateJWT2Validationtext_field.setEnabled(status)
            self._updateJWT1ReplaceString2Text_field.setEnabled(status)
            self._updateJWT2ValidationButton1.setEnabled(status)
            self._addIfNotExist_JWT2ValidationCheckbox.setEnabled(status)
        self._updateJWT3ValidationCheckbox.setEnabled(status)
        if self._updateJWT3ValidationCheckbox.isSelected():
            self._updateJWT3Validationtext_field.setEnabled(status)
            self._updateJWT3Validationtext_field2.setEnabled(status)
            self._updateJWT1ReplaceString3Text_field.setEnabled(status)
            self._updateJWT3ValidationButton1.setEnabled(status)
        if status:
            self.callbacks.registerSessionHandlingAction(ReplaceAccessToken(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-3A. Session Handling Action '{}' added to Burp Session Handling Rules. TOKEN-1 will be updated in request (+)".format(SHA_MOD_JWT_TKN))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_MOD_JWT_TKN:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-3A. Session Handling Action '{}' removed from Burp Session Handling Rules. TOKEN-1 will not be updated in request (-)".format(SHA_MOD_JWT_TKN))


    def toggleSHA_ReplaceRefreshToken(self, event):
        global SHA_MOD_REF_TKN
        status = event.getSource().isSelected()
        self._updateREF1ValidationCheckbox.setEnabled(status)
        if self._updateREF1ValidationCheckbox.isSelected():
            self._updateRefTknValidationtext_field.setEnabled(status)
            self._updateRefTknValidationButton1.setEnabled(status)
            self._addIfNotExist_RefTknValidationCheckbox.setEnabled(status)
            self._updateRefTknString1Text_field.setEnabled(status)

        self._updateREF2ValidationCheckbox.setEnabled(status)
        if self._updateREF2ValidationCheckbox.isSelected():
            self._updateRefTkn2Validationtext_field.setEnabled(status)
            self._updateRefTkn2Validation2text_field.setEnabled(status)
            self._updateRefTknString2Text_field.setEnabled(status)
            self._updateRefTkn2ValidationButton1.setEnabled(status)
        
        if status:
            self.callbacks.registerSessionHandlingAction(ReplaceRefreshToken(self.callbacks))
            self._statusLable1.setText("        (+) Update: SHA-3B. Session Handling Action '{}' added to Burp Session Handling Rules. TOKEN-2 will be updated in request (+)".format(SHA_MOD_REF_TKN))
        else:
            for sha in self.callbacks.getSessionHandlingActions():
                if sha.getActionName() == SHA_MOD_REF_TKN:
                    self.callbacks.removeSessionHandlingAction(sha)
                    break
            self._statusLable1.setText("        (-) Update: SHA-3B. Session Handling Action '{}' removed from Burp Session Handling Rules. TOKEN-2 will not be updated in request (-)".format(SHA_MOD_REF_TKN))
        
    def getTabCaption(self):
        return "SH+"

    def getUiComponent(self):
        scrollpane = JScrollPane(self._mainPanel)
        return scrollpane
        
class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._httpListener = MyHttpListener(callbacks)
        self._tab = MyTab(callbacks, self._httpListener)
        callbacks.setExtensionName("Session Handler Plus (SH+)")
        callbacks.customizeUiComponent(self._tab.getUiComponent())
        callbacks.addSuiteTab(self._tab)
        print("INFO: Session Handler Plus (SH+) extension loaded successfully!")
