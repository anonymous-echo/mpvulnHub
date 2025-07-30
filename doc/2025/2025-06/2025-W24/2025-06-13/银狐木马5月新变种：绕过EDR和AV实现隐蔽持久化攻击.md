> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjY2MTIzMw==&mid=2650623741&idx=1&sn=3bc1db0b6a4eb3005352664433f87cd1

#  银狐木马5月新变种：绕过EDR和AV实现隐蔽持久化攻击  
你信任的  亚信安全   2025-06-13 09:07  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bR0IKGlicqjDVR0iaZU1Us7AQNtEU79bh2a5ngVdElfBQvLktYXLztBgm5kicicExlMR7LXZwFJAQ4L1R7ydTn152w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bR0IKGlicqjDVR0iaZU1Us7AQNtEU79bh2HZBicj1WqbTaE59ibrW9tttLaOvicKGkkUdMcASIeQUCVDwukjxs32kAA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bR0IKGlicqjDVR0iaZU1Us7AQNtEU79bh29x4iak6jnAt1t1NicHZtXdK6a7L5fUnfOnJfMO47u4ics0YkCVJtOKf9w/640?wx_fmt=png "")  
  
Yin Hu  
  
**银狐木马5月新变种**  
  
**BootExecute机制绕过EDR和AV**  
  
**实现隐蔽持久化攻击**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icP6oGNEmKEQaZ09iaTwibqGibgPdbpYgbsP42nnWbX0QTQlmic1GmAzDoYQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bR0IKGlicqjDVR0iaZU1Us7AQNtEU79bh2KiceyoRZoia57Oo7osobuGaLxctABGR7MWh151ukzjibzYJeUZeBQaPyw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wM9Wh08JDNFQpKiaB20sCO8HfmNccroN5L2OHibgVGwMUmr6YM1KzfYM9ibfc6Xz41YMTDLV5h48h209jbZeE1qlQ/640?wx_fmt=png "")  
  
**前言**  
  
  
近日，亚信安全应急响应中心在日常狩猎中截获“银狐”变种，该变种不仅通过BootExecute机制绕过EDR（Endpoint Detection and Response）和AV（Antivirus）软件，还展示了新型持久化手段和多阶段攻击流程。其特点包括利用数字签名伪装、配置文件加载恶意DLL、异或加密解密PDB文件、内存中释放PE文件、拼接可执行文件片段以及通过注册表和BootExecute实现持久化。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icS5LCvd44UwmJyiaiaSdO9AwNMWT0yAibZ9RribrMueRYt7caSFF6vfMdEA/640?wx_fmt=png "")  
  
  
**技术细节分析**  
  
  
该变种样本目录有多个文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50ic0WMfy4aZxRKvrxEj9GAz0uRhyFxhLO3ZNue8APhGZmo2wvoribjYWNw/640?wx_fmt=png "")  
  
其中，可执行文件20250513.exe具有有效数字签名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icibLgiaa4CicY4oxEgIRKB6ib4IaO7QbnOfpLrTkXrRyz0XxqNO1o2y9CyQ/640?wx_fmt=png "")  
  
其通过配置文件20250513.exe.config加载恶意DLL  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icfUB3smXXUTdC4h7EM4SYBoCnKwiaaBc10ia9zyOibdlico0EIX8q6wmaUg/640?wx_fmt=png "")  
  
恶意DLL VSHive.dll实现了多个功能，包括移动目录中的文件到C:\Users\Public\Documents和C:\Programdata\xop-7  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icATnmGu3LTJIaK4N9IbsicKsX6KbHwFpUmc1cgicvAjiaDQxEW0xicyVMqA/640?wx_fmt=png "")  
  
申请管理员权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icPibXvwGVicAqice1JaL5fpBkibKGheyD9YeC5mAialv2csfz3QjoV1yzCnA/640?wx_fmt=png "")  
  
通过异或238(0xEE)进行对PDB文件进行简单解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icgibgpXvqn8wj2iceEXOWMsWMFgLBBdypoUicnzqMN46PX7QEy5GamX37Q/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icJhNOKrRJFXja3ZLZkn8zN2vN6hpK3fsF7vENjXiaAZkgPd1W6icSryVg/640?wx_fmt=png "")  
  
随后将解密出的shellcode 写入EXE的内存空间并执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icp2d6rNRMz3cV9IEG3nNCl2pkQsiaiaOCCJPRN0oECtzGPczaTefJYmiaw/640?wx_fmt=png "")  
  
在内存空间中解密释放出完整PE文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icBqiaGGZQK3HExcfAHLKS9R7CxhF91w6eKjk89eD0mmJAvO40uuYYaicw/640?wx_fmt=png "")  
  
其编译时间为2025/05/11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icFIWfQEzErDH88KZbSmCtSTvwia0hRzHTSwYorA6ScVrY2Cg7SzSeAQg/640?wx_fmt=png "")  
  
读取配置文件，外联C2服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icmWibbicN1nZOn1JcBeOoWxNHSAhqaVfSicypJoFwuhUeRQWqic43RtMDNA/640?wx_fmt=png "")  
  
通过InternetReadFile读取返回文件下载其他木马模块  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icxYtp7EBj22pEddkWfLOMialhcu0HmcUCQiblEw9JCqlZuGGQPiajXSibrA/640?wx_fmt=png "")  
  
其释放多个文件到指定目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icOdfxom1WnoaB3HAkf3kFS8oribsBDAHicrFmIiaHFPYxeZunMQpZqH4Wg/640?wx_fmt=jpeg "")  
  
其中，BEB为驱动程序，主要功能是设置注册表项  

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment，UserInitMprLogonScript
```

  
键值实现用户登录时自动执行恶意命令。其主要功能为拼接1.j和2.j为一个新文件TenioDL.exe，并执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icI6dKRqEoBk2G6JbBpGsFvfKTL44pzWSyhsTRtKqGYJyClqZZKFSYGw/640?wx_fmt=png "")  
  
1.j和2.j为一个可执行文件的拆分，通过拼接还原  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icegVSgJWWFF7EiaDMCpktC2jFz5qrSamyJ9xWhukRtQuib2aGfetyY1kw/640?wx_fmt=png "")  
  
1.reg则为HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager的键值  
  
BootExecuteNoPnpSync  设置其内容为BEB (上述可执行文件）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icUiagMhATeUuun6aZxg4EYZiaWR4HsV4KDOZN1dqLkaufbHAokOPBticXQ/640?wx_fmt=png "")  
  
该变种通过BEB.exe来完成持久化，利用了BootExecute EDR Bypass https://github.com/rad9800/BootExecuteEDR/tree/main  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50ic8wJQCJsqhgzkdo07NQ4YfCvFL3s5IY6CIWMeqOntQhj9FNmCv4wf5w/640?wx_fmt=png "")  
  
1.j+2.J拼接为TenioDL.exe 并执行，其执行后释放一个MSI安装包，并安装运行  
  
该MSI安装包将释放一个Console1.exe到相同目录（C:\Users\Publib\Documents)并执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icsUJGxdLPicxPYsXRGsBv0lgXs9dFxbyiaX7REAliacILpNRO0JcfFE6Cg/640?wx_fmt=png "")  
  
而Console1.exe，实际上与第一阶段内存中解密执行shellcode的流程相似，主要是读取同目录下的PDB文件并解密执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50ic0rDBtNagdPKVDOCibY2H1qU8TKs5YRutLqqV4vtFzsxpWmMluALtINQ/640?wx_fmt=png "")  
  
读取完成PDB文件后，创建wusa.exe并将解密的shellcode注入到该进程中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icPwOFMibAXjjcNAzIg6dxTnpCRzGStVZvIcJuibeBZGfg49b6ziazaJ5hw/640?wx_fmt=png "")  
  
wusa进程外联C2，获取其他木马模块  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icIeShH5ORhzeicYlEPpbwqYh5e3n7xBmA3sF0DXVdv2BicJZniaRnsRrYQ/640?wx_fmt=png "")  
  
  
  
  
**IOC**  
  
  
  
**样本Hash：**  
  
686d911aa537ed09b27ec9bbfbd3eaab  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icP6oGNEmKEQaZ09iaTwibqGibgPdbpYgbsP42nnWbX0QTQlmic1GmAzDoYQ/640?wx_fmt=png "")  
  
  
  
  
**总结**  
  
  
此次截获的“银狐”变种通过复杂的多阶段攻击和巧妙的持久化机制，展示了网络攻击技术的不断进化。其利用BootExecute绕过EDR/AV的手段，以及通过拼接文件和注入shellcode等技术，都体现了攻击者的高超技巧和精心设计。面对这样的威胁，企业和个人用户必须保持高度警惕，及时更新安全防护措施，加强系统监控和漏洞管理。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icP6oGNEmKEQaZ09iaTwibqGibgPdbpYgbsP42nnWbX0QTQlmic1GmAzDoYQ/640?wx_fmt=png "")  
  
  
  
  
**通用处置建议**  
  
  
- 全面部署安全产品，保持相关组件及时更新  
  
- 保持系统以及常见软件更新，对高危漏洞及时修补  
  
- 不要点击来源不明的邮件、附件以及邮件中包含的链接  
  
- 请到正规网站下载程序  
  
- 采用高强度的密码，避免使用弱口令密码，并定期更换密码  
  
- 尽量关闭不必要的端口及网络共享  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icP6oGNEmKEQaZ09iaTwibqGibgPdbpYgbsP42nnWbX0QTQlmic1GmAzDoYQ/640?wx_fmt=png "")  
  
  
  
  
**亚信安全产品解决方案**  
  
  
ATTK是亚信安全研发的疑难病毒检测工具，不仅可以高效收集系统信息，还具备强大的病毒检测和查杀能力。  
  
  
ATTK银狐专杀工具集成了梦蝶引擎的最新能力，包含10万条以上的启发式规则，机器学习模型和海量的云查杀病毒库。其中，梦蝶云查杀库新增每周350万+病毒样本检测能力，并建立了转向流程将流行样本和银狐木马加入本地特征库。  
  
  
**01**  
  
**亚信安全勒索治理方案**  
  
亚信安全建议通过高级威胁监测与治理产品对客户内网从网络流量、邮件以及文件等容易遭受黑客病毒攻击的维度进行全方位的检测，并通过终端检测与响应EDR进行攻击行为的溯源与验伤，锁定攻击源头与攻击方式。  
  
  
通过本地威胁情报中心以及统一的安全运营平台基于病毒情报特征进行规则更新，并统一策略下发至云、网、边、端各个安全产品对木马病毒进行拦截阻断，防止病毒在内网环境中的进一步传播。  
  
  
**02**  
  
**企业文件系统防护方案**  
  
针对黑客团伙利用伪造正常业务系统文件传播病毒的情况，亚信安全高级威胁文件沙箱DDAN作为专注于动态检测病毒文件的沙箱产品，可有效检测病毒文件，防护客户企业文件系统安全。  
  
  
**03**  
  
**企业邮件系统防护方案**  
  
针对黑客团伙利用钓鱼邮件传播病毒的情况，亚信安全信桅高级威胁邮件防护系统DDEI作为专注于钓鱼邮件防治的国内TOP级邮件网关产品，对钓鱼邮件的检出与拦截率超过95%，对垃圾邮件的综合过滤率达到99.5%，可有效防治黑客通过邮件的方式传播病毒的行为。  
  
  
通过邮件网关DDEI的内置沙箱深度分析附件中的木马，通过统一威胁运营平台将有害的附件情报同步到全网终端检测与响应设备实现自动遏制。  
  
  
联动路径:亚信安全信桅高级威胁邮件网关(DDEI) ==>本地威胁情报中心==>统一威胁运营平台==>终端检测与响应(EDR)  
  
  
**亚信安全建议**  
  
  
亚信安全认为，尽管许多组织已实施网络安全防护措施，但他们仍然遭受勒索攻击。这主要是因为现有的安全策略大多针对传统勒索软件，未能意识到这种攻击形式已演变成一个复杂的侵害网络，并形成了庞大的犯罪产业。许多企业忽视了攻击手法的多样性和发展趋势，导致防御措施难以应对新型威胁。  
  
  
因此，必须重新审视和升级安全策略，以适应不断变化的网络环境，开启关键日志收集、配置IP白名单规则、进行主机加固、部署入侵检测系统、建立灾备预案，并在遭遇勒索软件攻击时及时断网并保护现场，以便安全工程师排查。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEsfh1gw8pUyLosdJx4E50icP6oGNEmKEQaZ09iaTwibqGibgPdbpYgbsP42nnWbX0QTQlmic1GmAzDoYQ/640?wx_fmt=png "")  
  
  
  
  
  
 了解亚信安全，请点击  
**“阅读原文”**  
  
