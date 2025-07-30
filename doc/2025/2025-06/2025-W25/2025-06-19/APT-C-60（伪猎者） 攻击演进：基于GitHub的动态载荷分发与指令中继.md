> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyMjk4NzExMA==&mid=2247506307&idx=1&sn=917d291b3f14b349263a9b0a2f115323

#  APT-C-60（伪猎者） 攻击演进：基于GitHub的动态载荷分发与指令中继  
原创 高级威胁研究院  360威胁情报中心   2025-06-18 10:02  
  
**APT-C-60**  
  
    
**伪猎者**  
  
APT-C-60（伪猎者）是一伙以持续监控受影响用户、窃取相关信息为目的朝鲜半岛APT组织。我们于2018年发现该组织的活动，溯源分析最早的攻击活动可疑追溯到2014年。受影响用户大部分为涉韩的政府、经贸、文化有关的企事业单位，以及劳务咨询公司。  
###  一、概述   
  
近期，360高级威胁研究院在日常狩猎中发现APT-C-60组织攻击者通过滥用GitHub等可信云平台构建隐蔽指令通道，显著提升攻击隐匿性。  
  
本次攻击下列技术演进特征：  
  
可信服务平台滥用：构建GitHub（指令中继、前置载荷存储） + Bitbucket（后门载荷存储）的架构，实现动态载荷分发，增强攻击隐蔽性。  
###  二、技术解析   
#### 1.多阶段载荷投递流程  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="142" style="border:solid windowtext 1.0pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="text-align: center;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><b><span leaf="">阶段</span><span lang="EN-US"><o:p></o:p></span></b></p></td><td style="border:solid windowtext 1.0pt;border-left:none;mso-border-left-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="text-align: center;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><b><span leaf="">技术实现</span><span lang="EN-US"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:1;page-break-inside:avoid;"><td data-colwidth="142" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><strong><span style=""><span leaf="">初始入侵</span></span></strong><span lang="EN-US"><o:p></o:p></span></p></td><td style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">鱼叉式钓鱼邮件</span><span lang="EN-US"><span leaf="">+VHDX</span></span><span leaf="">虚拟磁盘附件（内含</span><span lang="EN-US"><span leaf="">LNK</span></span><span leaf="">诱导文件）</span><span lang="EN-US"><span leaf="">→</span></span><span leaf="">触发白程序加载</span><span lang="EN-US"><span leaf="">txt</span></span><span leaf="">中的恶意代码，释放</span><span lang="EN-US"><span leaf="">Install</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;page-break-inside:avoid;"><td data-colwidth="142" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><strong><span style=""><span leaf="">持久控制</span></span></strong><span lang="EN-US"><o:p></o:p></span></p></td><td style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">Install COM</span></span><span leaf="">劫持驻留</span><span lang="EN-US"><span leaf=""> +  </span></span><span leaf="">机器指纹</span><span lang="EN-US"><span leaf="">UID</span></span><span leaf="">生成 → 可信服务通信（</span><span lang="EN-US"><span leaf="">Statcounter</span></span><span leaf="">回传</span><span lang="EN-US"><span leaf="">/GitHub</span></span><span leaf="">轮询等待</span><span lang="EN-US"><span leaf="">Uid.txt</span></span><span leaf="">文件指令）</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;mso-yfti-lastrow:yes;page-break-inside:avoid;"><td data-colwidth="142" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><strong><span style=""><span leaf="">远控载荷执行</span></span></strong><span lang="EN-US"><o:p></o:p></span></p></td><td style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mc0888chsnq"><span leaf="">多样本多级解密（</span><span lang="EN-US"><span leaf="">Xor+Base64</span></span><span leaf="">）</span><span lang="EN-US"><span leaf="">→ Backdoor</span></span><span leaf="">加载 → 插件化扩展功能</span><span lang="EN-US"><o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3LIxRrby8ANd3f1TN07VDHG1DSJuMiakhyEYP4d0xCD1NT8cVgOgZq1A/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
（图注：攻击流程图红色框选部分为本轮攻击新增技术点，VHDX投递方式在2024年已有记录，Backdoor Install、Backdoor组件则最早可追溯至2018年。）  
#### 2.GitHub工程化分析  
  
攻击者GitHub仓库中的文件按功能可分为四类：  
  
2.1   
测试工程：2025年1月初上传的测试工程（文档/加密数据/Txt），内含加密的合法DLL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3WZtRlqn1XS4uCBmyQ8bcScRPw5AbpGIPlOkic2F92xayULRZzu47j3Q/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2.2   
版本管理：组件版本信息维护  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna31Q9lma97zbhZ5KpaxJMSQeHib8BUC7Jic2G3Df84pdU8KcT4kODnKWsQ/640?from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2.3   
指令下发：采用明文"机器指纹UID.txt"格式存储，指令存在三种形式  
  
1）下一段载荷URL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3y4u2cIZr2uDagdQgNnIXbqrgSCf3GEYkmGe9uVX3e3yEsgT3iaOLmVQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2）JS动态指令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3VbwVaShanPQTZe1GlSYVeKasIicpykLh0iarrwbGyVsmQNXBmiaiaoiaNEw/640?wx_fmt=png&from=appmsg "")  
  
3）目录遍历指令(历史已使用)  
  
![]( "")  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3iaJJLWOhbe31MwbjQiblBvdgtYWOoDCB5FiaTmR1No0agGfyMJUPesWgA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2.4   
加密载荷：文件体积≥120KB，使用Xor加密（密钥：u8b34ys8j5yogq7r32bm），扩展名不固定，绝大部分功能分类为Install 或 Backdoor Install。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna33sAgdCCpHscawYOQia5CEyQEQbODDGm8kuheLoJCOHv3Nl6YeJ96vXg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
经过我们对现有捕获的Github仓库进行分析，观察到下列载荷分发策略：  
  
1）对于部分新增受害机器首次指令为读取指定文件夹路径内容，二次指令才会下发载荷。            
  
2）批量生成Backdoor Install组件，核心功能相同但参数差异化。            
  
3）采用"限定设备共享样本"机制确保单样本仅在小范围设备传播。            
  
4）部分机器存在存在短时间内重复下发相同功能样本情况，可能与终端免杀相关。如DESKTOP-O40JMI2在同日被植入三个变体：trans.tmp/ser2.tmp/ser2s.tmp   
#### 3. 攻击组件关键点样本分析  
##### 3.1 UsrClassCache.dat（MD5: 1afcdf065669868e038a5fab934c28d2 Installer)）  
  
该组件为VHDX虚拟文件系统中释放的文件，功能用于执行Github项目指令功能。  
  
1）使用LoadLibraryW自身行为做类持久化操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3LXgiccnokv8VZ4nyA68NxzYO54oCfHhz7lcrnUmicyOfrLtDPW3U2N6w/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2）生成机器标识ID，通过磁盘信息和机器名来构建。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3229YXEcBKRAn8G0jdJbk7ux2ySQG3UkuiafXglh1LGzsIyiaTPjPUfkQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
3）为了避免静态检测，使用异或3形式对所需系统API字符串编码，程序执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna31eNPrgUuCazgBeeoVIibv1XAd2znRLZ4ESLEYMvPjabVwISsOcMLt2Q/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
4）通过网站计数器回传机器名、用户名、文件等相关信息，辅助攻击人员决定是否在Github中下发指令。  
  
请求 Url 通过异或3解码，当前样本Url https[:]//c[.]statcounter[.]com/13075150/0/caa8d685/1/  
  
请求时构造请求头，请求头内容包含：  

```
Referer: LIVE &#34;收集文件信息次数&#34;,&#34;下载文件的次数&#34; > %userprofile% / UID
UA：Onedrive/25.0
```

  
其中%userprofile% 为%userprofile%系统变量对应的目录，UID为前面生成的机器标识ID。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3elVdicaN9DEtKZv7KPPHycJtBdUpFJ7OrSvY6odptdWjzE59TjMicCVA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
当回传机器相关信息后，攻击者会手动在Github上创建机器对应的Txt文档。  
  
5）Github处理函数，当前样本在该函数中硬编码 (异或3) 三个Github工程 Url，通过冗余节点确保攻击链可用性。  
  
https[:]//raw[.]githubusercontent[.]com/goldbars33/ozbdkak33/refs/heads/main/  
  
https[:]//github[.]com/fenchiuwu/class2025/raw/refs/heads/main  
  
https[:]//github[.]com/football2025/class2025/raw/refs/heads/main/Master.txt  
  
其中前两个请求时，会携带UID(标识ID)路径，即确认对应项目中是否存在UID.txt文件，第三个Url是直接指定的txt文档。假如上述关注的文档存在，根据文档进行分发处理逻辑下载和执行逻辑处理或遍历文件逻辑。  
  
例如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3JJhTo7hamKJwwls1GykCUNXQtnphLU3pH6RkYYkxxHJW6IUltzsSrw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
下载和执行逻辑，下载的文件会存放在%LocalAppdata%\Microsoft\Windows\WebCache\WebCacheV.jfk:![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3iaV04YLAAKfAk5mVPniavERicDwelfX1sCjDKmQnLIt7evWMaW5tZF5sw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3Kq4vv3V3Mfr7lBpvYGJBxUeBc1dbvwokPuB2CWDnJ8OZDK5ENz1nwA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
当前样本使用u8b34ys8j5yogq7r32bm 密钥进行xor解码后续载荷。![]( "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3BxRAgNEFV5aHZqKpAricmdsP0VPH5k7c7YG2O7Fyflicq5AcpohdLYFQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
解码载荷后进行加载。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3iareicfNfDDzrkClLbib1ZGPticMQrhzgZryObB6OnVK9r7gF5SbluklNg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
上传目标文件夹数据逻辑：  
  
遍历目标文件夹上传数据到c[.]statcounter[.]com/13075150/0/caa8d685/1/中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna30ykHRtK6XiazM76dfdWWKLyzUN9hdDheKPr3feXicyu3uMmnR7BMxAhw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
3.2  
第二阶段执行载荷：Backdoor Installer (MD5: df58cd2b90db1960c8ac30f57839e513)  
  
1）初始化载荷配置信息，Backdoor载荷安装路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3UKId5C7udAMZOel9TIBLEYz4eT5sBk6UN7S4laIZlyVWpd2iaPT2EmQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2）判断当前机器是否已被感染，若未被感染则劫持系统Com {64B8F404-A4AE-11D1-B7B6-00C04FB926AF}组件实现Config.dat持久化操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3890NpXaKUEppUJ89RG9YjF8wDu7rY5HNo8YeyZ8bicAXRhI19Jv67gw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3mEXQhftvfnMDNvTJJj08vUEZwCJltfbNjfJLx6YbIZ2tY5icdJUxB7w/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
3）通过校验Backdoor载荷的本地文件(AppData\\Local\\Microsoft\\Edge\\cache\\Config.dat)是否存在，大小是否匹配，如果两项对不上重新执行下载逻辑。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3daQCvIUergZor4VicRfelogOaadcYD07bsPnxcFDJXqAS58dKeuicjUw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
临时下载文件名构造  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna37zZJhEd9F25po6coGRcw67icx3uv7tyVrbGsHbicWgRWBqJEcxSOfJHQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
4）对下载的下一段Backdoor载荷使用base64+特定密钥xor解码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3DiaR11x80YvvXeOt2HZbhhSRibOlzzzlvy7lZxJYAcBkp1z1M4GZjzkg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
3.3   
  
Backdoor  
 Config.dat (  
MD5：b3b0366a5696ab4a733cbfb0dddcc563)：  
  
1）此组件为Backdoor，启动时初始化配置信息，其中包含如下  
  
Backdoor版本3.1.10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna31MPGpz7q8N8PV8nl7VAkKAn4L3a73ibYHfLNMFF93Sl7AicjXxIyn3IA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
Backdoor支持指令下述指令  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="text-align: center;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><b><span leaf="">指令</span><span lang="EN-US"><o:p></o:p></span></b></p></td><td data-colwidth="230" style="border:solid windowtext 1.0pt;border-left:none;mso-border-left-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="text-align: center;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><b><span leaf="">功能</span><span lang="EN-US"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:1;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">procspawn</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">创建子进程</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">proclist</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">获取进程列表</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">prockill</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">关闭进程</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:4;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">diskinfo</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">获取磁盘信息</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:5;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">download</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">从远程下载文件</span><span lang="EN-US"><span leaf="">(</span></span><span leaf="">加密</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:6;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">downfree</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">从远程下载文件</span><span lang="EN-US"><span leaf="">(</span></span><span leaf="">未加密</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:7;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">upload</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">上传指定文件或目录</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:8;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">cancel</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">取消</span><span lang="EN-US"><span leaf="">\</span></span><span leaf="">停止操作</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:9;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">cmd</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">其他</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:10;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">screenupload</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">上传屏幕截图</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:11;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">screenauto</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">设置定期上传屏幕截图</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:12;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">turn on</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">增加指令循环频率</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:13;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">turn off</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">降低指令循环频率</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:14;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">cmd.exe /c</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">其他</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:15;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">cd</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">设置新的工作目录</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:16;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">ddir</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">遍历目录</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:17;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">ddel</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">删除文件或目录</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:18;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">ld</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">加载库文件，调用</span><span lang="EN-US"><span leaf="">extension</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:19;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">uld</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">卸载库文件，调用</span><span lang="EN-US"><span leaf="">stopextension</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:20;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">attach</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span leaf="">加载库文件</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:21;mso-yfti-lastrow:yes;page-break-inside:avoid;"><td data-colwidth="162" style="border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:
  solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US"><span leaf="">detach</span><o:p></o:p></span></p></td><td data-colwidth="230" style="border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .75pt;mso-border-left-alt:solid windowtext .75pt;mso-border-alt:solid windowtext .75pt;padding:3.75pt 3.75pt 3.75pt 3.75pt;"><p style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mc0cstbphkx"><span leaf="">卸载库文件</span><span lang="EN-US"><o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3K0dLiaocvOxqPcWZ72UvbDFNh8mTSeCaUnzDTFseHW9Y9kibibOLKRRxQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
  
通信C2  
  
![]( "")  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3Y8Cq8cuyD7DZHYSjwg2RibVEettl4yygXMpFiaW4zTmia7b9EuvpoVA5w/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
2）关注appdata%\Microsoft\SystemCertificates\My\CPLs 目录下的文件，该目录下的文件是Plugin 插件文件，当存在文件时尝试执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3B9FwiaVaNnUy8acibibWrLAArKRGPaXgrRict1TGaAYaPA5tNg145Dz0LA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3ICENOAJeLo6qnsuwNq0bD9gpvNR4nj4LW13O3tCf5Iy9TAGEcTgugg/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3zvciccRB1mmZZD2Q33C7wxDCCSicET5mTkcObcGex8rTgJI8vPicUar0A/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
Plugin 插件  
导出函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3uphMbIOOhd8qTa8icR5lqPSREkDugvMdwbw0Fj2jJq7uXq3nibAM9v4g/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
部分扩展组件执行内容(键盘记录程序)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3nDk2CooRBx1fqPEYCm1fvxnUtFhia1NDeSHbDiaHaVruTv5Wicfob7CQg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3SPObiaA8o5jm6Z9ay8o5TENjCHfia6tiblmpnI2KzIBhiatyIBIA2pcepA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
###  三、归属研判   
  
1. 从通信特征、指令、字符串解码(Xor3 、Xor2、Xor2 -1)逻辑形式均符合历史捕获的APT-C-60样本特征。  
  
Backdoor 通信特征与历史样本相同：  
  
如uid前导请求  

```
a001=cc0c2ffe71cf06f8bc907b4a1276d586&a002=7257ea57978efc6bcbcc05f48447a5b9&a003=uid&a004=JbMpXS9eAA==
```

  
a004的JbMpXS9eAA==是Backdoor配置内容 userid$$$$GOLDBAR中的GOLDBAR，数据的生成是通过非标准版的RC4编码+Base64编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3fLoPibhw6kX5GAibZVtZt9iaeLofYsP8UfAEcSUiccwMWp5CYlNwN5ibRnQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
Backdoor 核心处理逻辑上与历史样本相同：拆分多线程处理，请求逻辑、接收与反馈逻辑、屏幕监视Auto上传逻辑、文件上传逻辑、指令逻辑处理。先对对应线程判断是否存在，若不存在则进行创建。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3zicHekWMicXhrajplK7JaHoyULNe67FZggF00y3aBXmBQkicbobaGyRVQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
细节逻辑部分与之前样本类似，没有太大的变化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3PXZUdHwMyU2ciavMQmGrvXPUG3s16BiaYv8tBrfPbicR4rYof58290P2g/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
2. Backdoor 通信协议密钥以及通信协议方式与之前捕获样本相同。  
  
通信过程中敏感内容使用 RC4采用非标准算法 ，密钥90b149c69b149c4b99c04d1dc9b940b9  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3U0nS4uFVicdWPp3eLwiaXib3iaLWM1wRb9xGAMyMF7yjYnL1giajASZhtew/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
此组织的非标准算法比标准算法增强下面两个部分：  
  
(1) KSA(密钥调度算法) 增强，初始化S轮数从标准1轮修改为3轮。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3NvM2INkWHvbsviayQyaSG3iaVxfgia5hP3P0yTIfm8zJsSEUxv6A6iaVaw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
(2) PRGA(伪随机生成算法)混淆增强，增加额外的混合值，并通过动态索引计算以及多次XOR获得密钥流字节K  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3ibUc9Efc5IQkQkwXkBaOZkicr4vMCbtyDSvIqW5aghsQuhY8WCibKcz8g/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
3. 从Github项目操作时间来看(已转换为中国时区)符合APT-C-60特征。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppxh2alyC9vYQIHTWD0wna3CicbqUTC7krz5Ljj1CxcmvqS6Bf1IicsTvLvfyjzN6yKN3al4qvtUxicg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
 四、防范排查建议   
  
为了防范和排除此类攻击，我们建议采取以下措施：  
  
1. 提高警惕：对于收到的任何不明来源的电子邮件附件或链接，务必保持警惕。不要轻易点击或下载这些附件或链接。  
  
   
2. 安全意识培训：加强员工的安全意识培训，教育他们如何识别钓鱼邮件和恶意文件，以及如何正确处理可疑邮件。  
  
3. 邮件过滤和扫描：使用强大的邮件过滤系统来阻止钓鱼邮件和恶意附件进入您的邮箱。此外，定期扫描邮件系统以检测潜在的威胁。  
  
4. 文件扫描和防病毒软件：安装并及时更新可靠的防病毒软件，确保其能够自动扫描所有下载的文件，并检测和阻止恶意软件。  
  
5. 系统和应用程序补丁：保持操作系统、应用程序和网络设备的最新补丁更新，以修复已知漏洞，减少被利用的风险。  
  
6. 权限控制：限制用户执行某些类型的文件，如LNK文件，以防止恶意文件被执行。实施严格的访问权限管理，以减少攻击者的操作空间。  
  
7. 数据备份和恢复：定期备份重要数据，并确保能够快速恢复数据以应对潜在的安全事件。  
  
   
  
**附录 IOC**  
  
C2：  
  
66.85.161[.]186  
  
File：  
  
1afcdf065669868e038a5fab934c28d2   
  
df58cd2b90db1960c8ac30f57839e513   
  
b3b0366a5696ab4a733cbfb0dddcc563   
  
Github项目：  
  
goldbars33/ozbdkak33  
  
fenchiuwu/class2025  
  
football2025/class2025  
  
boygem436/repo  
  
goldbars33/ozbdkak33  
  
kithatart/repo1  
  
其他公共服务：  
  
https[:]//c[.]statcounter[.]com/13075150/0/caa8d685/1/  
  
https[:]//bitbucket[.]org/clouds999/glo29839/downloads  
  
  
**参考**  
  
  
[近些年APT-C-60（伪猎者）组织使用的载荷分析](https://mp.weixin.qq.com/s?__biz=MzUyMjk4NzExMA==&mid=2247505493&idx=1&sn=2260fa98c61cff9236bfea3e11059200&scene=21#wechat_redirect)  
  
  
https://blogs.jpcert.or.jp/en/2024/12/APT-C-60.html  
  
  
**团队介绍**  
  
  
TEAM INTRODUCTION  
  
**360****高级威胁研究院**  
  
360高级威胁研究院是360数字安全集团的核心能力支持部门，由360资深安全专家组成，专注于高级威胁的发现、防御、处置和研究，曾在全球范围内率先捕获双杀、双星、噩梦公式等多起业界知名的0day在野攻击，独家披露多个国家级APT组织的高级行动，赢得业内外的广泛认可，为360保障国家网络安全提供有力支撑。  
  
  
