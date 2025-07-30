#  一款容器镜像漏洞扫描器-Trivy   
原创 CatalyzeSec  CatalyzeSec   2025-01-17 10:48  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
介绍  
  
Trivy是一款全面而多功能的安全扫描器。Triv  
y 的扫描器可  
以查找安全问题，并确定可以找到这些问题的目标。  
  
目标（Trivy 可以扫描的内容）：  
- 容器镜像  
- 文件系统  
- Git 存储库（远程）  
- 虚拟机映像  
- Kubernetes  
扫描（Trivy 可以发现的内容）：  
- 正在使用的操作系统包和软件依赖项 (SBOM)  
- 已知漏洞 (CVE)  
- IaC （基础设施即代码工具）问题和错误配置  
- 敏感信息和机密  
- 软件许可证  
Trivy 支持大多数流行的编程语言、操作系统和平台。想获取更多功能信息可以查看官方文档：  
```
https://trivy.dev/latest/docs/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
安装  
  
Trivy 可在大多数常见环境中使用。  
  
一、Linux：  
```
mkdir trivy
cd trivy
wget https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_Linux-32bit.tar.gz
tar -zxvf trivy_0.58.1_Linux-64bit.tar.gz
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylmkrlziaKLQ9JwwQbgUKyXsVV92jrKeB5P2cUpPb3RtgwV7jBk3eY6NicDaejAX8B4Ir0M0yEmeJhg/640?wx_fmt=other&from=appmsg "")  
  
二、Windows  
```
https://github.com/aquasecurity/trivy/releases/latest/下载二进制文件
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylmkrlziaKLQ9JwwQbgUKyXsZ5ePVOSoqEZMHrdtbSTxg05gEeZ7mEnoDnuHCbr94CfH71iaE6rzSJA/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylmkrlziaKLQ9JwwQbgUKyXsZ5ePVOSoqEZMHrdtbSTxg05gEeZ7mEnoDnuHCbr94CfH71iaE6rzSJA/640?wx_fmt=other&from=appmsg "")  
  
解压即可运行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylmkrlziaKLQ9JwwQbgUKyXsg2c04Vp4JhpoibyTNMYhiaiamCzdf4ibWB4bUNicWnFD6LTJmpicWALwmtYw/640?wx_fmt=other&from=appmsg "")  
  
更多内容请参见安装文档：  
```
https://trivy.dev/latest/getting-started/installation/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
使用  
  
首次使用trivy需要下载trivy-db，该数据库  
下载和更新都比较慢，有条件的可以使用科学上网，也可以去源下载db并设置指向。之后可以使用"--skip-db-update --skip-java-db-update"跳过更新  
```
trivy image --input [镜像名/镜像tar包]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylmkrlziaKLQ9JwwQbgUKyXswK6ScJsztiaT22rXxI5adoziaP7gXUrDdA4MwhAGDtdnPBxibnNLZSyTw/640?wx_fmt=other&from=appmsg "")  
```
更详细功能使用可以访问项目地址查看：https://github.com/aquasecurity/trivy/
```  
  
**知识星球**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ymDTrPbHabRNmmuREXMTwia3Yu6kHWCgEFZxXPVnTkaNVUwv7m9gJfRDI5VOiavYpaaBYrW3BpNWRjg/640?wx_fmt=png&from=appmsg "")  
  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
  
