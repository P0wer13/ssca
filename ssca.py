#!/usr/bin/env python
# -*- coding:utf-8 -*-


import time
import sys
import datetime
import smtplib
import mimetypes
import os,json,requests
import tornado.ioloop
import tornado.web
import tornado.httpclient
from tornado.escape import json_decode
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.header import Header
from urlparse import *

reload(sys)
sys.setdefaultencoding('utf8')
requests.packages.urllib3.disable_warnings()

#pwd= os.path.split(os.path.realpath(__file__))[0]
pwd = "C:\\Users\\Administrator\\Desktop\\awvs"
tarurl = "https://******.****.com:3443/"
apikey="1986****0a5b3df4dea9c97028d5f3c06e936****1f646ea9c974659****4328"
headers = {"X-Auth":apikey,"content-type": "application/json"}

#邮件告警函数
def mysendmail(sub, content, reiv_mailist, attachs=''):
    #mail_host = "smtp.exmail.qq.com"  # 设置服务器
    mail_host = 'smtp.exmail.qq.com'
    mail_user = "security@qq.com"  # 用户名
    mail_pass = "***************"  # 口令

    sender = 'security@qq.com'
    receivers = reiv_mailist  # 接收邮件列表，可设置为QQ邮箱或者其他邮箱

    msg_part = MIMEMultipart()
    mail_content = MIMEText(content, 'plain', 'utf-8')
    msg_part['From'] = Header("security@qq.com", 'utf-8')
    msg_part['To'] = Header("******@qq.com", 'utf-8')

    subject = sub# 邮件主题
    msg_part['Subject'] = Header(subject, 'utf-8')

    msg_part.attach(mail_content)

    # xlsx附件
    if attachs != '':
        for attachname in attachs:
            mimetype, encoding = mimetypes.guess_type(attachname)
            maintype, subtype = mimetype.split('/', 1)

            attach = MIMEBase(maintype, subtype)
            fp = open(attachname, 'rb')
            attach.set_payload(fp.read())
            fp.close()
            encoders.encode_base64(attach)
            att_name = Header(attachname, 'gb2312')
            attach["Content-Disposition"] = "attachment; filename=%s" % att_name
            msg_part.attach(attach)

    try:
        smtpObj = smtplib.SMTP()
        smtpObj.connect(mail_host, 25)
        smtpObj.starttls()
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, msg_part.as_string())

    except smtplib.SMTPException, e:
        print(str(e))

    return True

def addtask(reason,url=''):
    #添加任务，返回任务id
    data = {"address":url,"description":reason,"criticality":"20"}
    response = requests.post(tarurl+"/api/v1/targets",data=json.dumps(data),headers=headers,timeout=30,verify=False)
    result = json.loads(response.content)
    print('add_tesk.....')
    print(result)
    yb = str(result)
    if 'Feature not allowed' in yb:
        sub='wvs认证过期'#邮件题目
        content='错误原因：content=%s ' % yb
        reiv_mailist=['******@qq.com']
        my_mail=mysendmail(sub,content,reiv_mailist)
    print('target_id: '+result['target_id'])
    return result['target_id']

def setlogin(task_id):
    data = {"login":{"kind":"automatic","credentials":{"enabled":True,"username":"security@qq.com","password":"*********"}}}
    try:
        response = requests.patch(tarurl + "/api/v1/targets/" + task_id + "/configuration",data=json.dumps(data),headers=headers,timeout=30,verify=False)
        print(response.status_code)
    except Exception as e:
        print(str(e))
        return

def startscan(task_id):
    #创建扫描,返回扫描id
    data = {"target_id":task_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
    try:
        response = requests.post(tarurl+"/api/v1/scans",data=json.dumps(data),headers=headers,timeout=30,verify=False)
        result = response.headers
        print('start_scan....')
        print(result)
        scan_id = result['Location'].split('/')[4]
        return scan_id
    except Exception as e:
        print(str(e))
        return

#
def get_scan_session(scan_id):
    #获取scan_session_id
    try:
        response = requests.get(tarurl+"/api/v1/scans/"+scan_id,headers=headers,timeout=30,verify=False)
        result = json.loads(response.content)
        print('get_scan_sessoion...')
        print(result)
        scan_session_id = result['current_session']['scan_session_id']
        print('scan_session_id: '+scan_session_id)
        return scan_session_id
    except Exception as e:
        print(str(e))
        return


def get_scan_gk(scan_id,scan_session_id):
    #有扫描状态等很多信息
    #获取扫描概况
    try:
        response = requests.get(tarurl+"/api/v1/scans/"+scan_id+'/results/'+scan_session_id+'/statistics',headers=headers,timeout=30,verify=False)
        result = json.loads(response.content)
        print('get_scan_gk...')
        print(result)
        print('获取扫描概况包括状态: .............')
        print('status: '+result['status'])
        return result
        #next_run
    except Exception as e:
        print(str(e))
        return


def get_report_url(scan_id):
    # 生成scan_id的扫描报告
    data = {"template_id":"11111111-1111-1111-1111-111111111112","source":{"list_type":"scans","id_list":[scan_id]}}
    try:
        response = requests.post(tarurl+"/api/v1/reports",data=json.dumps(data),headers=headers,timeout=30,verify=False)
        result = response.headers
        print(result)
        report = result['Location'].replace('/api/v1/reports/','/reports/download/')
        print(report)
        return tarurl.rstrip('/')+report+'.html'
    except Exception as e:
        print(str(e))
        return

def down_report(url):
    r = requests.get(url, verify=False)
    with open("report.html", "wb") as code:
        code.write(r.content)


def scan(reason,url):
    #创建任务,获取任务id
    try:
        target_id = addtask(reason,url)
    except Exception as e:
        sub='系统上线前漏洞扫描任务错误'#邮件题目
        content='错误原因：%s' % (str(e))#邮件正文
        reiv_mailist=['******@qq.com']
        my_mail=mysendmail(sub,content,reiv_mailist)
        try:
            print "Wait 15 seconds to continue scanning."
            time.sleep(15)
            target_id = addtask(reason,url)
        except Exception as e:
            try:
                print "Wait 30 seconds to continue scanning."
                time.sleep(30)
                target_id = addtask(reason,url)
            except Exception as e:
                sub='系统上线前漏洞扫描任务错误'#邮件题目
                content='错误原因：%s' % (str(e))#邮件正文
                reiv_mailist=['*******@qq.com']
                my_mail=mysendmail(sub,content,reiv_mailist)
                print(str(e))
                return




    #设置扫描权限
    setlogin(target_id)
    #启动扫描，获取扫描id
    scan_id = startscan(target_id)


settings = {
    'static_path': os.path.join(os.path.dirname(__file__), "static"),
}
class RiseHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def post(self, *args, **kwargs):
        self.finish("Ture")
        print 'Uid Start processing!'
        try:
            data=json_decode(self.request.body)
            print"******"
            print data
            print "*****"
            logfile = pwd + "\\" + time.strftime('%Y%m%d',time.localtime(time.time())) +"_log.txt" 
            with open(logfile, "a") as code:
                code.write(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+" "+str(data)+"\n")
                code.close()            
            uid=data['deliveryId']
            order = data['content']
            for line in order:
                reason={'emails':line['emails'],'buildId':line['buildId'],'uid':str(uid),"data_sources":line['data_sources']}
                reason=json.dumps(reason)
                client=tornado.httpclient.AsyncHTTPClient()
                s_url=line['domain']
                if (s_url.find("http://")== -1) and (s_url.find("https://") == -1):
        			s_url="http://"+s_url
                res = yield scan(reason,s_url)
                
        except BaseException,e:
            print e
            
        else:
            print 'uid:'+str(uid)+' Finish processing!'
    def set_default_headers(self):
        self.set_header('Content-type','application/json;charset=utf-8')

# application对象中封装了：路由信息，配置信息
application = tornado.web.Application([
    (r"/rise", RiseHandler),
],**settings)

if __name__ == "__main__":
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
