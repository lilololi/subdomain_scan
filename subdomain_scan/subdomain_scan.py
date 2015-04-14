# -*- coding: utf-8 -*-
# <nbformat>3.0</nbformat>

# <codecell>
import optparse
import Queue
import threading
import dns.resolver
import time
from optparse import OptionParser
import sys


class subdomain:
        def __init__(self,target,name_file,thread_num,output):
                self.target=target
                self.name_file=name_file
                self.thread_num=thread_num
                self.scancount=0
                self.findcount=0
                self.lock=threading.Lock()
                self.resolvers = [dns.resolver.Resolver() for i in range(thread_num)]
                self.load_dns_server()
                self.load_sub()
                self.load_next_sub()
                outfile=target+".txt" if not output else output;
                self.output=open(outfile,'w')
                self.outfile=open(outfile,'w')
                self.ip_dict={}
                
        def load_dns_server(self):
                dns_server=[]
                with open('dns_servers.txt') as f:
                    for line in f:
                            server = line.strip()
                            if server.count('.')==3 and server not in dns_server:
                                    dns_server.append(server)
                self.dns_server=dns_server
                self.dns_count=len(dns_server)
                
        def load_sub(self):
                self.queue=Queue.Queue()
                with open(self.name_file) as f:
                        for line in f:
                                sub = line.strip()
                                if sub:
                                        self.queue.put(sub)
        
        def load_next_sub(self):
                next_sub=[]
                with open('next_sub.txt') as f:
                    for line in f:
                        sub=line.strip()
                        if sub and sub not in next_sub:
                                next_sub.append(sub)
                self.next_sub=next_sub
                
        def update_scan_count(self):
                self.lock.acquire()
                self.scancount+=1
                self.lock.release()
                
        def print_progress(self):
                self.lock.acquire()
                msg = '%s found |%s remaining |%s scanned in %.2f seconds'%(self.findcount,self.queue.qsize(),self.scancount,time.time()-self.starttime)
                sys.stdout.write('\r'+'                                 '+msg)
                sys.stdout.flush()
                self.lock.release()
                
        def scan(self):
                thread_id=int(threading.currentThread().getName())
                self.resolvers[thread_id].nameservers=[self.dns_server[thread_id % self.dns_count]]
                self.resolvers[thread_id].lifetime=1.0
                self.resolvers[thread_id].timeout=1.0
                while self.queue.qsize()>0:
                    sub=self.queue.get()
                    try:
                            url_scan_domain=sub+'.'+self.target
                            #print "try  "+url_scan_domain
                            answers=self.resolvers[thread_id].query(url_scan_domain)
                            isrecord=False
                            if answers:
                                for answer in answers:
                                    self.lock.acquire()
                                    if answer.address not in self.ip_dict:
                                        #print answer.address
                                        self.ip_dict[answer.address]=1
                                        #print self.ip_dict
                                    else:
                                        #print "answer.address in self.ip_dict"
                                        self.ip_dict[answer.address]+=1
                                        if self.ip_dict[answer.address]>10:
                                            isrecord=True
                                    self.lock.release()
                                    #print isrecord
                                    if isrecord:
                                        self.update_scan_count()
                                        self.print_progress()
                                        continue
                                    self.lock.acquire()
                                    self.findcount+=1
                                    #print self.findcount
                                    ips=','.join([answer.address for answer in answers])
                                    #print ips
                                    msg=url_scan_domain.ljust(30)+ips
                                    #print msg
                                    sys.stdout.write('\r'+msg)
                                    sys.stdout.flush()
                                    self.outfile.write(url_scan_domain.ljust(30)+"\t"+ips+"\n")
                                    self.lock.release()
                                    for i in self.next_sub:
                                        self.queue.put(i+'.'+sub)
                                        #print i+'.'+sub
                    except Exception, e:
                        pass
                    self.update_scan_count()
                    self.print_progress()
                self.print_progress
        def  run(self):
            self.starttime=time.time()
            for i in range(self.thread_num):
                t=threading.Thread(target=self.scan,name=str(i))
                #print self.scan
                #print str(i)
                t.start()

if __name__ == '__main__':
	parser=optparse.OptionParser('usage: subdomain.py  xxx.com')
	parser.add_option('-t','--threads',dest='threads_num',default=10,type='int',help='Number of Threads.Default =10')
	parser.add_option('-f','--subfile',dest='subfile',default='subnames.txt',type='string',help='TXT for scanning the domain.Defalut is subnames.txt')
	parser.add_option('-o','--outfile',dest='outfile',default=None,type='string',help='Which file you want to save.Defalut is {target}.txt')
	(options,args)=parser.parse_args()
	if len(args)<1:
		parser.print_help()
		sys.exit(0)
	d=subdomain(target=args[0],thread_num=options.threads_num,name_file=options.subfile,output=options.outfile)
	d.run()        
                

# <codecell>


