#  Vivotek CC8160 固件栈溢出漏洞复现分析   
原创 林昀  山石网科安全技术研究院   2024-06-24 11:33  
  
### 一、固件提取  
  
http://download.vivotek.com/downloadfile/downloads/firmware/cc8160firmware.zip  
  
```
```  
  
  
路径_CC8160-VVTK-0113b.flash.pkg.extracted/_31.extracted/_rootfs.img.extracted/squashfs-root  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DuOm8dvcSSzQY4k8f5hmiaUce5VklNzemDZoJfTzAic9U2bz543jLHgbw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DtAueibYDJwciaCBnLlkEgwIPFZ10zHoBqG1QKO5ueh6dbbSnLN7CbO9Q/640?wx_fmt=png&from=appmsg "")  
  
确定架构为ARM、小端、32位  
### 二、官方揭露阅读  
  
conkielength过长导致的栈溢出
在ida搜索一下Content-Length  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DZtnBq32ktd2gXekyrAwibPxR8eP1VGx3zlUISYEIedrgGAFVUBwZI6g/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DTbhG64hfqUOuAwiciaFv1dXF4Cly6HbOckUQvkf7iafcZQwHnGSGWsxibg/640?wx_fmt=png&from=appmsg "")  
  
没有检查length的长度，全部赋值到dest这个栈上变量  
### 三、环境搭建  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DRGke4ub8HoiaficffkFs3Q93vCSNxVe1mPuGCwd5qKSicictzWDmhD1cBA/640?wx_fmt=png&from=appmsg "")  
  
分析一下httpd文件吧
搜一下字符串  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6Dl7iaiadOaJAhRxia0sLjysTpWwiaQVM80YqJlgLV0ibEErI3zJhTMRF6jWA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DEhUTsQ7oIL0gnPY2M3RibxPr18pWskia9NYh3RLqstAUxRkbNJJKtjzw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DfytBzNYRyDzelLKSvVp4ZUEvHOSPna8LsVribT4FHNia93loTSLcBK5Q/640?wx_fmt=png&from=appmsg "")  
  
发现缺少条件，但是测试的我直接给他patch掉，就不用去搞这些配置文件了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DES7DsLHhtNjN9WzGjhhZoJ6hC6v53X0BvGkP30ibre1BmO3DDWmz4icg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6D0AlkvGVnBwDUrN23peib6n0Czp7IhyYUqFTqmulGXuBjAB8gwYI8eew/640?wx_fmt=png&from=appmsg "")  
  
没有文件配置文件也可以跑，但是后面会用到文件中的内容，导致ddos  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6Do3CFD6miaqQB3Vx60bHqW03W2uJsz1cSibTu1t6v8iaYrv6FQicrxWNH3g/640?wx_fmt=png&from=appmsg "")  
  
在文件系统里面搜索该配置文件，在./_31.extracted/defconf/_CC8160.tar.bz2.extracted/_0.extracted/etc/conf.d/boa/boa.conf，把该/etc目录拷到../mnt/flash/目录下面，即可修复该问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6D18yIIDib2VE8nGIiaPxXUpfu0yFFvbYaX6WXEI2uicOP0O5wyzcRq8bxw/640?wx_fmt=png&from=appmsg "")  
  
跑起来了，跟着反馈继续跟进  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DY2ibicNwtGuxXKKWQ9oOK95uuMTahNf33SLaiaV8bv5z8lAok91SWZpMw/640?wx_fmt=png&from=appmsg "")  
  
gethostbyname()：用域名或主机名获取IP地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DysxoFP3vpYo7JANTeTSBcvVNou6qArYHDU4kDxcuLUOrGojZRgicf6Q/640?wx_fmt=png&from=appmsg "")  
  
```
```  
  
  
需要把他们俩改为一致就可以跑了
笔者的用户名是ubuntu  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DBO2DY7ia6vmcrXicKxh434EUhFiaDxiabV2NubjC8AXxdPrUrfAsrJRpeA/640?wx_fmt=png&from=appmsg "")  
  
qemu宿主机环境搭建  
  
```
```  
  
  
设置tap0网卡net.sh  笔者的理解是  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DHWFgI5armIpnyia5aY5iab4tn5OCXQdwk5TxYpf49NzD1ZWx1GJKOkKg/640?wx_fmt=png&from=appmsg "")  
  
```
```  
  
  
qemu宿主机启动脚本start.sh  
  
```
```  
  
  
给qemu机器设置网卡ip  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6D8650kngMZSKQjibtl3qlfacve3KFyYZChKn4EltIAEbWbk3YtwgzLyw/640?wx_fmt=png&from=appmsg "")  
  
将文件传到宿主机  
  
```
```  
  
  
启动服务  
  
```
```  
  
  
启动之后我宿主机连不上去，很奇怪  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DzmJG8ZrABsFPliaicibTmareLAIsUiaOucctZhNVGaWkUpo6K5Mlb4rDnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
发现是httpd文件被笔者patch错了
还需要对机器进行挂载和赋权操作  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DQN9hjUE3AiaaVBB1Uc7yfU8iaeccHj7QvPCAjdptowxJjD3gTRp5Ep1Q/640?wx_fmt=png&from=appmsg "")  
### 四、验证poc  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DVVfyBgZ7ruczib7HzOIPPHMHicXRd1Ag4NvicSFf2yoOfensCibvjuVHlg/640?wx_fmt=png&from=appmsg "")  
  
进行调试发现  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DtXmbgPIjicxvJ3FLZzRc7qTO1LquFAoFa0CnukDk1G6Mib1UHZnuL9iaw/640?wx_fmt=png&from=appmsg "")  
  
溢出量为0x33，开了nx保护
得到基地址  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DXNpnfWaC658HOft1ZZoJdqCgvKTgSThvmUTbqloJj4Axc6bCoKqHiaw/640?wx_fmt=png&from=appmsg "")  
### 五、漏洞利用  
  
rop链构造  
  
```
```  
  
  
```
```  
  
  
tips1 ：为什么不用，  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DULfHj7ajmNbgnVymjEIpNsIicaD1M9KSAbPxC5Kn2FtqZtASBDGJoDw/640?wx_fmt=png&from=appmsg "")  
  
完整poc  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKLAj3woQxBiaIzdNZUTW6DzLOWiaLicKIdjsMBsNZP6DlQf3xsujPK3E6LLpG70YF0iakBh6GSeJXdg/640?wx_fmt=png&from=appmsg "")  
  
把shell反弹到6666端口，nc上就是一个shell了  
  
