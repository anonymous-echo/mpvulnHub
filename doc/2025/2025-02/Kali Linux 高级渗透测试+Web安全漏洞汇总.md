#  Kali Linux 高级渗透测试+Web安全漏洞汇总   
 计算机与网络安全   2025-02-11 23:57  
  
**加入知识星球：**  
**网络安全攻防（HVV）**  
**下载文件**  
  
********  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VcRPEU1K2ocfPKYrdnhTNJ3Uz6qIq3DqiaNjtgL6Ql3A41v50yo9hEKHu7qV5xHQpcrdZq9hDF86MVmlsMQXF1Q/640?wx_fmt=jpeg&from=appmsg "")  
  
**本篇仅提供星球内下载，不提供人工获取**  
  
# 会员进群和文件下载指南  
  
  
第一部分　攻击者杀链  
第1章　走进Kali Linux  
1.1　Kali Linux  
1.2　配置网络服务和安全通信  
1.2.1　调整网络代理设置  
1.2.2　使用安全Shell保护通信安全  
1.3　更新Kali Linux  
1.4　配置和自定义Kali Linux  
1.4.1　重置超级用户密码  
1.4.2　添加普通用户  
1.4.3　加速Kali运行  
1.4.4　与Microsoft Windows共享文件夹  
1.4.5　用TrueCrypt创建加密文件夹  
1.5　第三方应用程序的管理  
1.5.1　安装第三方应用程序  
1.5.2　作为普通用户运行第三方应用程序  
1.6　渗透测试的有效管理  
第2章　确定目标——被动侦察   
2.1　侦察的基本原则  
2.2　开源情报  
2.3　DNS侦察和路由映射  
2.3.1　WHOIS  
2.3.2　DNS侦察  
2.3.3　映射路由到目标  
2.4　获得用户信息  
2.4.1　收集姓名和电子邮件地址  
2.4.2　收集文件元数据  
2.5　分析用户密码列表  
第3章　主动侦察和漏洞扫描  
3.1　隐形扫描策略  
3.1.1　调整源IP栈和工具识别设置  
3.1.2　修改数据包参数  
3.1.3　使用匿名网络代理（Tor和Privoxy）  
3.2　识别网络基础设施  
3.3　枚举主机  
3.4　端口、操作系统和发现服务  
3.4.1　端口扫描  
3.4.2　指纹识别操作系统  
3.4.3　确定主动服务  
3.5　采用综合侦察应用  
3.5.1　nmap  
3.5.2　recon-ng框架  
3.5.3　Maltego  
3.6　漏洞扫描  
第4章　漏洞利用  
4.1　威胁建模  
4.2　使用在线和本地漏洞资源  
4.2.1　Metasploit框架  
4.2.2　利用易受攻击的应用程序  
4.3　使用Armitage的多目标渗透  
4.3.1　Armitage 测试团队  
4.3.2　Armitage攻击脚本  
4.4　绕过IDS与反病毒侦测  
第5章　后期利用——行动的目的  
5.1　绕过Windows用户账户控制  
5.2　对已入侵的系统进行快速侦察  
5.3　找到并提取敏感数据——掠夺目标  
5.4　创建附加账户  
5.5　使用Metasploit工具进行后期渗透活动  
5.6　在已入侵主机上提升用户权限  
5.7　使用incognito重放身份验证令牌  
5.7.1　使用Windows凭据编辑器操作访问凭据  
5.7.2　从管理员升级到系统管理员  
5.8　访问新账户实现横向升级  
5.9　消除痕迹  
第6章　后期利用——持久性  
6.1　破解现有的系统和应用程序文件进行远程访问  
6.1.1　启用远程服务  
6.1.2　启用远程Windows终端服务  
6.1.3　启用远程虚拟网络计算  
6.2　使用持久代理  
6.3　使用Metasploit框架保持持久性  
6.3.1　使用metsvc脚本  
6.3.2　使用persistence脚本  
6.4　使用Metasploit框架创建一个独立持久代理  
6.5　重定向端口来绕过网络控制  
6.5.1　示例1——简单端口重定向  
6.5.2　示例2——双向端口重定向  
第二部分　交付阶段  
第7章　物理攻击与社会工程学  
7.1　社会工程工具包  
7.1.1　网络钓鱼攻击曝光  
7.1.2　使用网站攻击向量——Java小程序攻击方法  
7.1.3　使用网站攻击向量——凭据收割攻击方法  
7.1.4　使用网站攻击向量——标签钓鱼攻击方法  
7.1.5　使用网站攻击向量——综合攻击网页方法  
7.2　使用PowerShell字母数字的shellcode注入攻击曝光  
7.3　隐藏可执行文件与伪装攻击者的URL  
7.4　使用DNS重定向攻击的升级攻击  
7.5　物理访问与敌对设备  
第8章　利用无线通信  
8.1　配置Kali实现无线攻击曝光  
8.2　无线侦察  
8.3　绕过一个隐藏的服务集标识符  
8.4　绕过MAC地址验证  
8.5　破解WEP加密  
8.6　攻击WPA和WPA2  
8.6.1　暴力攻击曝光  
8.6.2　使用Reaver攻击无线路由器曝光  
8.7　克隆接入点  
8.8　拒绝服务攻击曝光  
第9章　基于Web应用的侦察与利用  
9.1　对网站进行侦察  
9.2　漏洞扫描器  
9.2.1　扩展传统漏洞扫描器功能  
9.2.2　扩展Web浏览器功能  
9.2.3　具体网络服务的漏洞扫描器  
9.3　使用客户端代理测试安全性  
9.4　服务器漏洞  
9.5　针对特定应用的攻击  
9.5.1　暴力破解访问证书  
9.5.2　数据库注入攻击曝光  
9.6　使用网站后门维持访问  
第10章　利用远程访问通信  
10.1　利用操作系统通信协议  
10.1.1　破解远程桌面协议  
10.1.2　破解安全外壳  
10.2　利用第三方远程访问应用程序  
10.3　攻击安全套接字层  
10.3.1　为SSLv2扫描配置Kali  
10.3.2　SSL连接的侦察  
10.3.3　使用sslstrip进行中间人攻击曝光  
10.3.4　针对SSL的拒绝服务攻击曝光  
10.4　攻击IPSec虚拟专用网络  
10.4.1　扫描VPN网关  
10.4.2　指纹识别VPN网关  
10.4.3　截获预共享密钥  
10.4.4　执行离线PSK破解  
10.4.5　确定默认用户账户  
第11章　客户端攻击技术详解  
11.1　使用恶意脚本攻击系统曝光  
11.1.1　使用VBScript进行攻击曝光  
11.1.2　使用Windows PowerShell攻击系统曝光  
11.2　跨站点脚本框架  
11.3　浏览器开发框架——BeEF  
11.4　BeEF浏览器的演练  
11.4.1　整合BeEF和Metasploit攻击  
11.4.2　用BeEF作为隧道代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W32CHRQ5lvDWPZuBRvNicHKCNeVSqF6BGicCgViaetJYbAD43cwCfynaCnQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3oqiaCZZyL2sH7LITXMpbwmBcm4kImRDOh2Zf0GBkJl7GjgTtcAe42Cw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W32t0MCL9cENMhb0XsHOAhePbSQibSfiaSKJnssMHfDVRbOeAKkUjDOxNA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3hNf8FKULz6NeJOBic22Dq9yPvyxXqy9JwHD7VzChYJKU7icjvb9iaQjJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3yga0nYuqV6Ssw2miaGF0mzvghY4aUsYbWfVmdxhEPJloacvbmHPgrdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3A8NbPsrv54JlXibhicib4bfLvMgW51o1nedNia7eBm3zwickIcRQImwHDvQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W37rWsaoFBwvmQQBXMvibCfucqJ6zQRcVG0ORNMkQmbIs5aiaBQrpsxLTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3xJicySat6lQKVd7ghf6cMicYOnS0QiaRnnibXYGOWQZbWVn320QwwCuuxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3vtdawdTwzHVTPuOBzHV7P6GquAnoxOib4Hbt5LDAGc3QlyR88RSP43A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3Xib5NTe0KQ52D1nVOicvWZC6iaib8vK4EZ53wwAwLq3WYIicSVcOsia7DKAA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3VpQ5ulmtVibdQaKXfCQtxxomHGIiciaU0zrJZ93pYqTGL4HNHImdRCVvQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3UtViapKJPriamwbPjSL6BPHUstgHGF8x77zNLkmg1D8FOKPTaf7qkJcw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3kThgwGRXvColH1KvSkI0iblS0gYicHL8ATCicxIBUNMr8IL3j4NPRLZXg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3HDQAqD9m99Fn82q6z2jnVibhBPlzAI5tGsxLjs99ic4KfGDXjBTfcVYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3gia241d1R66ueaWiaH8339Mmiaoz03XuGhexIFaWM7jKhtib7YKh2vWMYA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3I7HKXCiaMRGuMkFCTQljljBw9JwovTDUAcicwkHa4mc4oncoON3ZHPPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3BTUFcRGNHC3Yo3LDVibiarB9quMpbGaEmozsCmhDIPkq7ChxIUxvqaHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3lRCjNznPUBVPStTGn2VpMEedPogjhHqgxtb54FEZrhncZ5jW70XfLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3OSfJbOLTkPxeuD5Ss8gsl4ln0cSqJBxjUopGwmXicx4O84jibKIiaRZkw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3HWx1CkZ9iacNR4Y0EXvztTKb0bjUz2vDjOK7DhoNkialdeJ0jzSV1rxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3M5b0UjOAtiazP3Z33iaukyZHz4LndiaoHTfnKCWOiaXTHxpbsRRsQvebeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3ugr2PLwiauWjcgbbm7qsuduLfjFwzHQ1O5eu2ic53PK4MuvDBrP5M4Ow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3yHwpKNMvcprKmTribLGRqMz10nIWE18KaQ14DWXmiaBVKybEhRVlpRvg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W32MVZXHKRvia7oyyXITpmfOl5lFpaQB7WyQqGYqfVjP6tXGnRjNtxQHA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3G5V1YRTibntLOB9V8SKibpnDgkM0rUfTxEbDSXficSKuz8V8zQwhTJOibw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3AMyyWxqNC8Fbq2qE72SPKjoAFwQicjgcSuj7FyTQiagEXjyrEd7iasS1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W33YWbvQxiapymLKRkTz1yibYCN2ktzG6ZiaxcLW7ghka44uWzEMtHrtxGg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3BYxgibAnAdCBud49EiawuxbkYowY0DXFZsDQgrHvye2ju7iaz1aOQxcpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3wkdV1IROZ9dEibJyLMzCwasYpDNjsmzo7D6uVxiax4xuJLfvK0g4YIiag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3U5jnWngbdJHSSXYgJ6OHkNjqBxbZ7XicicocysCu8YJKlgkq9tZ03Otw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W310O9wjqo9VPNmCeYChrWj7D9p5JXtu1WK56ibTk41U10tXGYw5icT3qg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3mUOzaM0FlLRNYJtKfTZXiaZUCvykAZBI1taC1Z2XbUhpZbiasLVLseYQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3azxTwVtS8nJ7nciaQHMK4eh9qLdL5kjxwMDgOibmLRyZCRy6ibVmIGoeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3paWN6quYwwbgqRdhKTicgY3t4fvQfNFYJ9wpTRe9WThYibpCRj8DqN3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W35CribeBdssKyrg7FrltDwXx5P36qABgS8c33U92sp9CbC4yEria8fnoQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3CGibSib7dQ2M5sPqxKVNZUriasYvcE93dXXKPZYMPxg69YwrfRwvKOBPg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3bzQvicKFeCQDbo8Pvrf5fiaia7CxUlr1Ez5RjjQAJc0XkY9xMP5uibxQZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3YUQhXxu3DxSJeIYH2J3W2qGAvibLdw8mbMGHSYhic0VficIcl1WPGicE6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3mDPzLL9xCicpqy6ta9wznxV74RyJ5JcY9AulicWyrbkozcLBtUXk3ibPg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W39zPN3GlnUdekr7lwO8IRwtcLPhxruPSKd2ibK7Lvw7HUkvIEMqTpf5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3jRpbkvXdQJBEBJAAlR1tuMSaaFNGTp2J4lXCXomzmSOIciaA5WHTHeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3RVOicSFZCeiaMoZfjBHF8KDbT5RUjnHb2nZqhb3FsLlNLUtpDbfuK3Ag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3tojpxqWUPnWM5yxXibP3DFvpFiaNLY9JwGGygqapoJnDicLd1qqHM6Tsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3N5kxe33Hf0GOh0FYJSh30iaLrd5XVJNWOewWfROibH1sbLZwrpvibWLibg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3CVrNDgnOr3FGHxBuPvnbXKwy1IPTibW7DG2ibubMmHytFUQb7kZVnJ9Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W36Jkr8WMRo7ZYicq0hkxyt11T6sqW5Kiaib2EqVAeR7wVgN6h4P0MpFeGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3kg5eDkn7JYEuuJCqB6jC3Ky7FI04eGicbRicuJpKncVvgwiaOhmBLzcvw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3qsXuwjgYBbafPFUuGY2KKFEia0RHes8LjqQGn39PkArAa1DQf2icUq8Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3KVZJ3mLJmFzPfgkZhiamib2Ueib8mcOVtKTCqMrdwuXtLbhF2yBbiaFB9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2oeByy9HlTLC1okZuk54C9W3BVPYsibSQsKtjROiaQcVvJWd0n0KzMbF0xD6UOeNicmibz9sQTW2sxy5qg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**|**  
 -  
  
