#  fastjson漏洞批量检测工具（7月12日更新）   
smallfox233  Web安全工具库   2024-07-15 22:13  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
1. 根据现有payload，检测目标是否存在fastjson或jackson漏洞（工具仅用于检测漏洞、定位payload）  
2. 若存在漏洞，可根据对应payload进行后渗透利用  
3. 若出现新的漏洞时，可将最新的payload新增至txt中（需修改格式）  
4. 工具无法完全替代手工检测，仅作为辅助工具使用  
0x02 安装与使用  
一、常用命令  
```
安装第三方库
pip3 install -r requirement.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

检测单个站点:
python3 JsonExp.py -u [目标] -l [LDAP服务地址]

根据请求包检测单个站点：
python3 JsonExp.py -req [目标.txt] -l [LDAP服务地址]

根据文本检测多个站点:
python3 JsonExp.py -uf [目标.txt] -l [LDAP服务地址]
```  
  
二、DNSlog检测，  
自定义地址，  
若出现dnslog回弹，可根据前面的编号去寻找对应的payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuUyN0ia6dKBHYINIhaobTF0ib7OnhyrDBO83iciaSBwLc4Bbn4D50ocKnGJg4grw5hBfy7B8IZNwzA2g/640?wx_fmt=png&from=appmsg "")  
  
三、随机地址，  
需挂全局代理才能访问并申请资源，使用此功能将对发包速度产生较大影响。  
若存在dnslog回弹结果，将会生成/result/xxx_dnslog.html文件，没触发dnslog则不会生成该文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuUyN0ia6dKBHYINIhaobTF0dp2O1SrKGAjtlv4CKZYzZWhfuG5pSw6zthmvibTzrFOMOQibbl7AriaQg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：  
https://pan.quark.cn/s/7305fc0953ff  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
不仅仅是一个工具库。。。。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8H1dCzib3Uibu7uX2oYjbbibndft14nzUMIoRia7UqCAgMXSZAu1iaBDWSWLLuFnyibwfOiaCLO7YXaC6qib8icgHXwoe3Q/640?wx_fmt=jpeg "")  
  
