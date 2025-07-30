#  XXE漏洞检测工具   
Weijin-wj  Web安全工具库   2024-12-11 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
这是一个 XXE 漏洞检测工具，支持 DoS 检测（DoS 检测默认开启）和 DNSLOG 两种检测方式，能对普通 xml 请求和 xlsx 文件上传进行 XXE 漏洞检测。  
0x02 安装与使用  
对普通请求进行检测，指定请求包为 1.txt，-d 添加 dnslog 链接，不加只进行 DoS 检测，如果不想使用 DoS 检测请添加 --nodos  
```
python3 XXECheck.py -t request -f 1.txt -d dnslog
```  
  
如果不指定请求包，则会生成检测 POC，手工检测  
```
python3 XXECheck.py -t request -d dnslog
```  
  
对  
 xlsx 上传功能进行检测，指定请求包为 1.txt，-d 添加 dnslog 链接，不加只进行 DoS 检测，如果不想使用 DoS 检测请添加 --nodos  
```
python3 XXECheck.py -t xlsx -f 1.txt -d dnslog
```  
  
如果不指定请求包，则会生成带有 POC 的 xlsx 文件，手工检测  
```
python3 XXECheck.py -t xlsx -d dnslog
```  
```

```  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：https://pan.quark.cn/s/40bd17579cd2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvibNgBy6sbFr3n7aYIvicmz12Fib9ibw637XCjsBH1lRZokibRtibUcytDiaehgjNhjQzvfv9tzG0Ed2MvQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtLSarUAfUlwmxjveAciaScbdECHpL0QZokAtiaH6yLh032pAE2oUeP27Kuxial0DXAqnnB7kKoWdZVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvibNgBy6sbFr3n7aYIvicmz1noEUJtzGeJTfIS6uSIr77oOeoibSM974IBibKiaq4Vk370I960Gse6y9Q/640?wx_fmt=png&from=appmsg "")  
  
