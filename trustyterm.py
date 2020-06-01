#!/usr/bin/env python


""" trustyterm """


try:
    import psyco # cpu improvment
    psyco.profile()
except:
    pass
import array
import fcntl
import glob
import mimetypes
import optparse
import os
import pty
import random
import re
import signal
import select
import sys
import threading
import time
import termios
import struct
import pwd
import Cookie
import json
from datetime import datetime, timedelta
try:
    from hashlib import sha1
except ImportError:
    import sha
    sha1 = sha.new
import qweb
import codecs
from socket import gethostname

import requests

utf8decoder = codecs.getincrementaldecoder('utf8')()
os.chdir(os.path.normpath(os.path.dirname(__file__)))

class SynchronizedMethod:

    def __init__(self,lock,orig):
        self.lock = lock
        self.orig = orig

    def __call__(self,*l):
        self.lock.acquire()
        r = self.orig(*l)
        self.lock.release()
        return r


class Reaper: # inactive ssh client processes killer

    WAKEUP_FREQUENCY=5

    def __init__(self,multi):
        self.multi = multi
        self.thread = threading.Thread(target = self.reaper_thread)
        self.thread.setDaemon(True)
        self.thread.start() # execute reaper_thread in  new daemon

    def reaper_thread(self):
        while True:
            time.sleep(Reaper.WAKEUP_FREQUENCY) # wait 5 sec
            self.multi.proc_kill_inactive() # kill ssh client idle for 2 minutes



class Multiplex:

    INACTIVE_PROCESS_TIMEOUT = 120    # secs


    def __init__(self):
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        self.proc = {} # map fd (pty master side) to {'pid':pid,'buf':'','time':time.time(),auth:True/False}
        self.lock = threading.RLock() # returns a new reentrant lock object (RLock Objects)
        self.thread = threading.Thread(target=self.loop) # thread with executable function = loop
        self.alive = 1
        self.session_closed = []
        for name in ['create','auth_fds','proc_read','proc_write','dump','die','run']:
            orig = getattr(self,name) # getattr(x, 'foobar') is equivalent to x.foobar
            setattr(self,name,SynchronizedMethod(self.lock,orig)) # setattr(x, 'foobar', 123) is equivalent to x.foobar = 123
        self.thread.start() # execute self.loop in a new thread

    def create(self,cmd_ssh=""):
        try:
            pid,fd = pty.fork()
        except OSError as e:
            print("pty_creation_error: " + str(e))
        if pid == 0: # child process
            try:
                fdl = [int(i) for i in os.listdir('/proc/self/fd')] # process' open fds
            except OSError:
                fdl = range(256) # fdl = [0..255]
            for i in [i for i in fdl if i>2]: # (0,1,2 are stdin/out/err)
                try:
                    os.close(i)
                except OSError:
                    pass
            cmd = ['/bin/sh','-c',cmd_ssh]
            env = {} # shell variables
            env["TERM"] = "linux" # kind of terminal
            env["PATH"] = os.environ['PATH']
            os.execvpe(cmd[0],cmd,env)
        else: # father process
            fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
            # map fd (pty master side) to {'pid':child pid,'term':Terminal(w,h),'buf':'','time':time.time(),auth:True/False}
            self.proc[fd] = {'pid':pid,'buf':'','time':time.time(),'auth':False,'sshd_resps':[],'sshd_tmp_resp':''}
            return fd # return fd of pty master-side

    def die(self):
        self.alive = 0 # WSGI is down

    def run(self):
        return self.alive # WSGI server state

    def auth_fds(self): # fds of authenticated session
        fds =  self.proc.keys()
        for fd in fds:
            if not self.proc[fd]['auth']:
                fds.remove(fd)
        return fds

    def proc_kill(self, fd):
        try:
            os.close(fd) # Close file descriptor fd
            os.kill(self.proc[fd]['pid'],signal.SIGHUP) # send SIGHUP to the process on the pty slave side(# SIGHUP is a signal sent to a process when its controlling terminal is closed)
            self.session_closed.append(fd)
        except (IOError,OSError):
            pass
        try:
            del self.proc[fd] # remove element with key=fd from the proc dict
        except:
            print("proc_kill_Unexpected error:", sys.exc_info()[0])

    def proc_kill_inactive(self):
        t = time.time()
        for i in self.proc.keys():
            t0 = self.proc[i]['time']
            if (t-t0) > Multiplex.INACTIVE_PROCESS_TIMEOUT:
                print('killing process ' + str(i))
                self.proc_kill(i)


    def proc_read(self,fd):
        ''' os.read reads up to 4096 bytes, so if cipher is longer I have to compose it by cuncatenating 4096 bytes chunks
        I understand when the cipher finished because sshd puts the 'g' letter at the end, which is not in the hex alphabet '''
        try:
            resp = os.read(fd,65536*2)
            l = resp.split('g')
            if(resp[-1]=='g'): # no truncation at the end
                if(self.proc[fd]['sshd_tmp_resp'] == ''): # no truncation at beginning, probability this is a single compl resp
    			    self.proc[fd]['sshd_resps'] += l
    	        else: # truncation at beginning, first element of l has to be merged with tmp resp to get the complete resp
		            trunc = l.pop(0)
		            compl_resp = self.proc[fd]['sshd_tmp_resp'] + trunc
		            self.proc[fd]['sshd_tmp_resp'] = ''
		            self.proc[fd]['sshd_resps'].append(compl_resp)
		            self.proc[fd]['sshd_resps'] += l
    	    else: # truncation at the end
		        if(self.proc[fd]['sshd_tmp_resp'] == ''): # no truncation at beginning 
		            trunc = l.pop()
		            self.proc[fd]['sshd_tmp_resp'] = trunc
		            self.proc[fd]['sshd_resps'] +=l
		        else: # truncation at the beginning
		            if(len(l)<=1):
		                # this is a part of a very long command
		                self.proc[fd]['sshd_tmp_resp'] += l.pop()
		            else:
		           	    # l[0] is the end of the truncated resp, and l[-1] is the beginning of another truncated resp
			            t1 = l.pop(0) # l[0]
			            t2 = l.pop() # l[-1]
			            compl_resp = self.proc[fd]['sshd_tmp_resp'] +t1
			            self.proc[fd]['sshd_resps'].append(compl_resp)
			            self.proc[fd]['sshd_resps'] += l
			            self.proc[fd]['sshd_tmp_resp'] = t2

            self.proc[fd]['time'] = time.time()

        except (KeyError,IOError,OSError):
            self.proc_kill(fd)

    def proc_write(self,fd,s):
        try:
            os.write(fd,s) # write the string s to SSH CLIENT
        except (IOError,OSError):
            self.proc_kill(fd) # kill SSH client process

    def dump(self,fd):
        try:
            if self.proc[fd]['sshd_resps']:
                return self.proc[fd]['sshd_resps'].pop(0) # proc[fd]['sshd_resps'] is a list of resps of sshd for the current session, so I get them in order
            else:
                return None
        except KeyError:
            return False

    def loop(self): # read pseudo terminals output from ssh client and write them on corresponding terminal objects
        while self.run(): # loop until WSGI is live
            fds = self.auth_fds() # authenticated session
            # select() system call block the program flow until one of n file-descriptors is ready to read
            i,o,e = select.select(fds, [], [], 0.001)
            
            for fd in i: # for every fd ready
                self.proc_read(fd) #
                #if len(i):
                    #time.sleep(0.2)

        for i in self.proc.keys(): # if WSGI server is down
            try:
                os.close(i) # close all pty
                os.kill(self.proc[i]['pid'],signal.SIGTERM) # and the processes on the slave-side
                #print 'close:'+str(i)
            except (IOError,OSError):
                pass




class TrustyTerm: # WSGI application

    def __init__(self,index_file='empty_index.html',token=None):
        self.files={} # web page files
        for i in ['css','html','js','ico','png']:
            for j in glob.glob('*.%s'%i): # search in current dir
                self.files[j]=file(j).read()
        self.files['index']=file(index_file).read()
        self.token=token # authorization token
        self.mime = mimetypes.types_map.copy() # MIME type dict
        self.mime['.html']= 'text/html; charset=UTF-8'
        self.multi = Multiplex()
        self.reaper = Reaper(self.multi)
        # session
        self.session = {} # Keys are TT_SIDs, Values are PTYs
        self.session_ip = {}

        # ================= NEW CODE =================
        self.session_to_auth = {}
        self.encrypted_setup_data = {}
        self.signat_setup_data = {}
        self.keystrokes_auth_fail = {}
        self.ssh_session_id = {} # Keys are TT_SIDs, Values are SSH_SIDs
        self.ttsid_srvrip = {} # Keys are TT_SIDs, Values are Server IPs
        self.tt_sid_decsig = {} # Keys are TT_SIDs, Values are Decrypted Signature of session
        # ============================================

        self.sessions_limit = 4
        self.sessions_user_limit = 2

    def __call__(self, environ, start_response):

        req = qweb.QWebRequest(environ, start_response, session = None)

        if req.PATH_INFO.endswith('/info'): # SSH connection request
            # init response
            req.response_headers['Content-Type']='application/json'
            resp = ''

            # SSH connection data
            username = req.REQUEST["user"]
            hostname = req.REQUEST["hostname"]
            port = req.REQUEST["port"]
            kp = req.REQUEST["kp"] # public key
            tt_sid = req.REQUEST["TT_SID"] # TT_SID (TrustyTerm Session ID generated by Browser)

            print("Received a request for a new TrustyTerm Session!\n\tUser: "+username+"\n\thostname: "+hostname+"\n\tTT_SID: "+tt_sid+"\n")

            self.ttsid_srvrip[tt_sid] = hostname # Needed in /encsig req path for sending Server the encrypted Digital Signature

            # user public key filename
            m = sha1()
            m.update(tt_sid)
            kp_file_path = '%s/users_kp/%s%s.pub' % (os.path.dirname(os.path.realpath(__file__)),username,m.hexdigest())

            # remote IP
            ip="unknown"
            if environ.has_key("REMOTE_ADDR"):
                ip = environ['REMOTE_ADDR'] # REMOTE_ADDR -> The IP address from which the client is making the request.
                if ip == "127.0.0.1" and environ.has_key("HTTP_X_FORWARDED_FOR"): # se la richiesta viene da localhost ma e' un forwarding
                    ip = environ["HTTP_X_FORWARDED_FOR"] # HTTP_X_FORWARDED_FOR -> environment variable that holds the actual origin address of web clients coming in through a proxy
            #print os.path.dirname(os.path.realpath(__file__))

            # SSH connection command
            ssh_connection_cmd = '%s/openssh_mod/ssh -i %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s@%s -p %s' % (os.path.dirname(os.path.realpath(__file__)), kp_file_path,username,hostname,port)

            # update dictionaries removing terminated sessions
            for closed_pty in self.multi.session_closed:
                for i in self.session.keys():
                    if self.session[i] == closed_pty:

                        del self.session[i]
                        del self.session_ip[i]

                        # ================= NEW CODE =================
                        del self.session_to_auth[i]
                        del self.encrypted_setup_data[i]
                        del self.signat_setup_data[i]
                        del self.keystrokes_auth_fail[i]
                        del self.ssh_session_id[i]
                        # ============================================

            del self.multi.session_closed[:]  #removes the contents from the list

            #print('SESSIONS = ' + ', '.join(map(str, self.session.values())))
            #print('PROCS = ' + ', '.join(map(str, self.multi.proc.keys())))
            #print self.multi.session_closed

            # check if there aren't too many open sessions
            if len(self.session) < self.sessions_limit:
                count = 0
                for i in self.session_ip.keys():
                    if self.session_ip[i] == ip:
                        count += 1
                if count < self.sessions_user_limit: # user session limit
                    try:
                        # save user public key
                        kp_file = open(kp_file_path,'a')
                        kp_file.write(kp)
                        kp_file.close()
                        # SSH session creation
                        term = self.session[tt_sid] = self.multi.create(ssh_connection_cmd) # fd of the child, so SSH Client PTY
                        print('New SSH session created.')
                        # print('SESSIONS = ' + ', '.join(map(str, self.session.values())))
                        # print('PROCS = ' + ', '.join(map(str, self.multi.proc.keys())))
                        
                        ssh_resp = json.loads(self.wait_ssh_sid(term)) # Getting SSH_SID from SSH Client
                        self.ssh_session_id[tt_sid] = ssh_resp['ssh_session_id'] # Creating matching between TT_SID and SSH_SID
                        print('SSH_SID from SSH Client: ' + ssh_resp['ssh_session_id']+'\n')

                        # AUTH
                        resp = self.wait_digest(term) # get JSON from SSH Client containing digest and hash algorithm
                        # remove public key file
                        os.remove(kp_file_path)
                        json.loads(resp) # will throw a ValueError if the string you pass can't be decoded as JSON
                        req.write(resp)
                        return req # Sending digest to Browser
                    except:
                        print("ssh_session_creation_error:", sys.exc_info()[0])
                        # delete session
                        if tt_sid in self.session:
                            del self.session[tt_sid]
                        if tt_sid in self.ssh_session_id:
                            del self.ssh_session_id[tt_sid]
                        del self.ttsid_srvrip[tt_sid]

                        #print('SESSIONS = ' + ', '.join(map(str, self.session.values())))
                        #print('PROCS = ' + ', '.join(map(str, self.multi.proc.keys())))
                        if resp != '': # get a Value Error from json.loads
                            resp = resp.rstrip() # what get from SSH client
                        else: # error happened at pty creation
                            resp = "SSH session creation failure."
                        r = '{"msg":"%s"}'%(resp)

                        req.write(r)
                        return req
                else:
                   req.write('{"msg":"user session limit exceeded"}')
                   return req
            else:
                    req.write('{"msg":"too many sessions on the server"}')
                    return req

        if req.PATH_INFO.endswith('/encr_sig'): # Browser has sent me the Encrypted Digital Signature and Encrypted AES Key
            if environ.has_key("REMOTE_ADDR"):
                ip = environ['REMOTE_ADDR']
                if ip == "127.0.0.1" and environ.has_key("HTTP_X_FORWARDED_FOR"):
                    ip = environ["HTTP_X_FORWARDED_FOR"]

            iv_hex = req.REQUEST["IV"] # getting IV from request params
            encSig_hex = req.REQUEST["EncSig"] # getting Digital Signature encrypted with AES-CBC from request params
            encKey_hex = req.REQUEST["EncKey"] # getting Aes Key encrypted with RSA-OAEP from request params
            tt_sid = req.REQUEST["TT_SID"]

            ssh_sid = self.ssh_session_id[tt_sid] # getting SSH_SID associated with TT_SID from dictionary

            # Sending to Server all the data
            resp = requests.get(url = "https://" + self.ttsid_srvrip[tt_sid], params = {'SSH_SID':ssh_sid, 'TT_SID':tt_sid, 'IV':iv_hex, 'EncSig':encSig_hex, 'EncKey':encKey_hex}, verify = False)
            del self.ttsid_srvrip[tt_sid] # no longer needed
            
            time.sleep(3) # Allowing Server to send back Decrypted Digital Signature

            if tt_sid in self.tt_sid_decsig:
            	# Server has sent back the Decrypted Digital Signature, I can send it to SSH Client
                decr_sig = self.tt_sid_decsig[tt_sid] # getting Digital Signature from TT_SID in the tt_sid_decsig dictionary

                pty = self.session[tt_sid] # pseudo-terminal connect to the SSH client
                self.multi.proc_write(pty,decr_sig+'\n') # write Signature to SSH Client to complete auth with SSHD
                del self.tt_sid_decsig[tt_sid] # no longer needed in the dictionary

                # wait auth response from SSH client (Timeout = t secs)
                auth_res = self.wait_auth_resp(pty,7)
                if auth_res['auth']: # auth succeed
                    self.multi.proc[pty]['auth']=True # terminal emulation can start
                    #resp = '{"msg":"AUTH_OK"'+',"ssh_session_id":"'+auth_res['ssh_session_id']+'"}'
                    resp = '{"msg":"AUTH_OK"}'
                    self.session_ip[tt_sid] = ip

                    # ================= NEW CODE =================
                    self.session_to_auth[tt_sid] = list()
                    self.keystrokes_auth_fail[tt_sid] = 0
                    self.encrypted_setup_data[tt_sid] = ""
                    self.signat_setup_data[tt_sid] = ""
                    self.ssh_session_id[tt_sid] = auth_res['ssh_session_id']
                    # ============================================

                    print('SSH Authentication succeed.')
                    print('IPs = ' + ', '.join(map(str, self.session_ip.values())))
                    print("total sessions = "+ str(len(self.session))+"\n")
                else: # auth failed
                    print('SSH Authentication failed.')
                    # delete session
                    if self.session[tt_sid] in self.multi.proc:
                        del self.multi.proc[self.session[tt_sid]]
                    if (tt_sid) in self.session:
                        del self.session[tt_sid]
                    if tt_sid in self.ttsid_srvrip:
                    	del self.ttsid_srvrip[tt_sid]
                    del self.tt_sid_decsig[tt_sid]
                    print('SESSIONS = ' + ', '.join(map(str, self.session.values())))
                    print('PROCS = ' + ', '.join(map(str, self.multi.proc.keys())))
                    resp = '{"msg":"AUTH_FAILED", "ssh_session_id": "None"}'
            else:
            	if self.session[tt_sid] in self.multi.proc:
                    del self.multi.proc[self.session[tt_sid]]
                if (tt_sid) in self.session:
                    del self.session[tt_sid]
                if tt_sid in self.ttsid_srvrip:
                    del self.ttsid_srvrip[tt_sid]
                print('SESSIONS = ' + ', '.join(map(str, self.session.values())))
                print('PROCS = ' + ', '.join(map(str, self.multi.proc.keys())))
                resp = '{"msg":"AUTH_FAILED", "ssh_session_id": "None"}'
            
            # response
            req.response_headers['Content-Type']='application/json'
            req.write(resp)
            return req


        if req.PATH_INFO.endswith('/decr_sig'): # Server has sent me the Decrypted Digital Signature
            decr_sig = req.REQUEST["DecrSig"]
            tt_sid = req.REQUEST["TT_SID"]
            #print("Decrypted Signature received: " + decr_sig)

            if decr_sig != "InvalidParams":
            	self.tt_sid_decsig[tt_sid] = decr_sig


        # ================= NEW CODE =================
        if req.PATH_INFO.endswith('/server_session_setup'):

            # Variable to check if the requested session was found
            session_found = 0

            # init response
            req.response_headers['Content-Type']='text/xml'

            # request session setup phase
            session_setup_phase = int(req.REQUEST["phase"])

            if (session_setup_phase == 1):
                # request SSH session ID
                ssh_session_id = req.REQUEST["ssh_session_id"]

                # find the TT_SID that corresponds to SSH_SID
                for s in self.session.keys():
                    if self.ssh_session_id[s] == ssh_session_id:
                        req.write('{"tt_session_id":"'+s+'"}')
                        session_found = 1
                        break

                if session_found == 0:
                    # TT_SID corresponding to SSH_SID not found, sending "None"
                    req.write('{"tt_session_id":"None"}')

            elif (session_setup_phase == 2): # Server has sent the TT_SID, the Encrypted Shared Secret, and the Digital Sig of Shared Secret
                # request encrypted data and TT_SID
                tt_sid = req.REQUEST["tt_session_id"]
                self.encrypted_setup_data[tt_sid] = req.REQUEST["encrypted_data"]
                self.signat_setup_data[tt_sid] = req.REQUEST["signat"]
                req.write('{"result":"Encrypted session setup data saved"}')

            elif (session_setup_phase == 3): # Browser asked for Encrypted Shared Secret and Digital Sig of Shared Secret
                tt_sid = req.REQUEST["tt_session_id"]
                req.write('{"encrypted_data":"' + self.encrypted_setup_data[tt_sid] + '", "signat":"' + self.signat_setup_data[tt_sid] +'"}')
                # del self.encrypted_setup_data[tt_sid]
                # del self.signat_setup_data[tt_sid]

            else:
                req.write('{"error":"Invalid phase number"}')

            return req


        if req.PATH_INFO.endswith('/notify_auth_fail'):
            # init response
            req.response_headers['Content-Type']='text/xml'

            # request trustyterm sid
            tt_sid = req.REQUEST["TT_SID"]

            # set variable to notify that auth failed
            self.keystrokes_auth_fail[TT_SID] = 1

            return req


        if req.PATH_INFO.endswith('/u'): # terminal emulation request
            # init response
            req.response_headers['Content-Type']='text/xml'
            # request values

            tt_sid = req.REQUEST["TT_SID"]
            ssh_sid = req.REQUEST["SSH_SID"]
            k = req.REQUEST["k"] # keypressed

            # get SSH session
            if (tt_sid) in self.session:
                pty = self.session[tt_sid]

                if(pty not in self.multi.proc): # This is the case where SSH session was deleted but TT_SID is still in self.session dict
                	req.write('SSH Session deleted')
                	return req

                # ================= NEW CODE =================
                # Check if keystrokes auth from server succeeded
                if (self.keystrokes_auth_fail[tt_sid] != 0):

                    #cleanup
                    if self.session[tt_sid] in self.multi.proc:
                        del self.multi.proc[self.session[tt_sid]]
                    del self.session[tt_sid]
                    del self.session_ip[tt_sid]
                    del self.ssh_session_id[tt_sid]
                    del self.ttsid_srvrip[tt_sid]
                    del self.keystrokes_auth_fail[tt_sid]

                    req.write('Keystrokes authentication failed')
                    return req
                # ============================================
            else:
                req.write('Invalid TT_SID')
                return req

            # if keypressed
            if k:
                resp = self.multi.proc_write(pty,k) # write k on pty (so to ssh client)

            # get screen update
            resp = self.multi.dump(pty)
            if resp:
                req.write(resp)
                req.response_gzencode = 1 # compress with gzip
                #print("Sending to Browser: ", resp)
                #print("IV|TAG|CIPHER LEN: ", len(resp))
            else:
                req.write('<?xml version="1.0"?><idem></idem>')
            return req

        else: # page loading request
            n = os.path.basename(req.PATH_INFO) # os.path.basename('/blabla.bla') -> 'blabla.bla'
            if n in self.files:
                req.response_headers['Content-Type'] = self.mime.get(os.path.splitext(n)[1].lower(), 'application/octet-stream')
                req.write(self.files[n]) # return file content
            elif (not self.token) or (req.REQUEST['token'] == self.token):
                req.response_headers['Content-Type'] = 'text/html; charset=UTF-8'
                #req.write(self.files['index']) # send index page
                req.write('')
            else:
                raise Exception('Not Authorized')
            return req  # return the response to WSGI application server

    def wait_ssh_sid(self,pty):
    	READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
        TIMEOUT = 7000 # 7sec
        poller = select.poll()
        poller.register(pty, READ_ONLY)
        events = poller.poll(TIMEOUT)
        for fd, flag in events:
            # Handle inputs
            if flag & (select.POLLIN | select.POLLPRI):
                resp = os.read(fd,65536)
                #print("READ FROM SSH CLIENT:["+ resp + "]")
        poller.unregister(pty)
        return resp.rstrip()

    def wait_digest(self,pty):
        READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
        TIMEOUT = 7000 # 7sec
        poller = select.poll()
        poller.register(pty, READ_ONLY)
        events = poller.poll(TIMEOUT)
        for fd, flag in events:
            # Handle inputs
            if flag & (select.POLLIN | select.POLLPRI):
                resp = os.read(fd,65536)
                #print("READ FROM SSH CLIENT:["+ resp + "]")
        poller.unregister(pty)
        return resp.rstrip()

    # ================= NEW CODE =================
    def wait_auth_resp(self,pty,timeout):
        t = time.time()
        session_id_regex = '"session_id":"[a-f0-9]+"'
        res = {'auth': False, 'ssh_session_id': "None"}
        not_done = True
        count = 0
        while not_done :
            i,o,e = select.select([pty], [], [], 1.0)
            for fd in i: # pty ready for read
                buf = os.read(fd,65536)
                #print("READ FROM SSH CLIENT:["+ buf + "]")
                a = buf.find('"msg":"AUTH_OK"')
                if a != -1:
                    if ((len(re.findall(session_id_regex, buf))) != 0):
                        res['ssh_session_id'] = json.loads("{"+re.findall(session_id_regex, buf)[0]+"}")['session_id']
                        res['auth'] = True
                        not_done = False
                    else:
                        res['auth'] = False
                        not_done = False
            count = count+1
            if time.time() - t > timeout:
                print("timeout auth response")
                res['auth'] = False
                not_done = False
        return res
    # ============================================

def main():
    parser = optparse.OptionParser()# Parser for command line option
    parser.add_option("-p", "--port", dest="port", default="8023", help="Set the TCP port (default: 8023)")
    parser.add_option("-l", "--log", action="store_true", dest="log",default=0,help="log requests to stderr (default: quiet mode)")
    parser.add_option("-i", "--index", dest="index_file", default="empty_index.html",help="default index file (default: trustyterm.html)")
    parser.add_option("-t", "--token", dest="token", help="Set authorization token")
    (o, a) = parser.parse_args() # parse_args() returns two values: options(an object containing values for all of your options e args(the list of positional arguments leftover after parsing options)
    print('TrustyTerm at http://localhost:%s/\n' % o.port)
    # WSGI app
    tt = TrustyTerm(o.index_file,o.token)
    try:
        # WSGI server
        qweb.QWebWSGIServer(tt,ip='localhost',port=int(o.port),threaded=1,log=o.log).serve_forever()
    except(KeyboardInterrupt,e):
        sys.excepthook(*sys.exc_info())
    tt.multi.die() # WSGI server is down


if __name__ == '__main__':
        main()
