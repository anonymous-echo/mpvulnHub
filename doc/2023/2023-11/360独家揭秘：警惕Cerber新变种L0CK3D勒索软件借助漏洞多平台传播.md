#  360独家揭秘：警惕Cerber新变种L0CK3D勒索软件借助漏洞多平台传播   
 360数字安全   2023-11-09 18:33  
  
****  
****  
近期，接到大量Linux系统用户反馈，  
**电脑中的文件被勒索软件加密**  
，被加密后的文件后缀均为.L0CK3D。经分析，这些用户感染的均是隶属于Cerber家族的勒索软件。本轮攻击主要是通过Confluence 数据中心和服务器中的不当授权漏洞进行传播（漏洞编号为CVE-2023-22518）。受该漏洞影响而遭到攻击的平台，覆盖了Linux与Windows等主流服务器操作系统。而需要特别说明的是，**360主动防御系统可在默认状态下对“利用该漏洞的攻击”进行拦截，部署360主动防御系统的平台无需担心。**  
  
  
**CVE-2023-22518漏洞简述**  
  
  
根据披露，当前Confluence 数据中心和服务器的所有版本，均受此不当授权漏洞影响。该漏洞允许未经身份验证的攻击者重置 Confluence，并创建 Confluence 实例管理员账户。利用这个新创建的账户，攻击者可以执行 Confluence 实例管理员可用的所有管理操作，从而导致系统机密性、完整性和可用性的完全丧失。  
  
  
此漏洞最初于2023年10月31日被公布，而  
360安全大脑监控到，利用该漏洞所展开的在野攻击，最早出现在2023年11月1日（仅在漏洞被公布的1天后）。  
  
  
**CVE-2023-22518攻击详情**  
  
  
根据  
360安全大脑捕获的攻击信息显示，攻击者会通过该Confluence漏洞调起cmd进程并创建powershell进程来加载攻击载荷。如下图所示，此步骤的漏洞触发操作便会被  
360主动防御系统直接拦截。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQPpjuicTqcYs55RyMGFB4wERdTNHQvkiaiaNVmrRMrCnSzZlkicR3005KsA/640?wx_fmt=png "")  
  
  
对上述脚本进行解码后得到的内容如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQJUTTUhELUic4JqLhb1niahSvITsAYKCmcFo0vXWibDpibllpCAhrtKB8rg/640?wx_fmt=png "")  
  
  
而根据上述代码中的下载信息，可获取到tmp.48脚本，其代码内容如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQNebKTAgFDLDONWE99ibonFC4d1GB7JeFCcjqBO4ARUyKE0K2tMbSp8A/640?wx_fmt=png "")  
  
  
根据代码分析，该脚本被执行后首先会定义一个名为Download_Execute的函数来构造一个.NET WebClient对象，并进行一些基本的参数初始化操作。之后，脚本会检查当前的Confluence服务器是否应使用指定的代理服务器。如果需要，脚本将使用该 Web 客户端下载指定的文件。否则，脚本将使用Internet Explorer组件对象模型 (COM) 来下载脚本。  
  
  
随后，脚本便会下载Cerber勒索软件的主体功能文件，并将其保存到临时文件夹中，进而命名为svcPrvinit.exe。完成后，附加参数“-b 9”以达到静默执行该进程而不显示窗口的目的。  
  
  
脚本的最后一行调用前文中定义的Download_Execute函数访问地址：193.176.179.41下载Cerber勒索病毒文件tmp.48.txt。  
  
  
**Cerber勒索软件简述**  
  
  
以Windows平台样本为例，对此次传播的勒索软件进行简要说明。  
  
**样本基本信息：**  
  
所属家族：Cerber  
  
病毒名称：Win32/Ransom.Generic.HwoCB9cA  
  
文件名：svcPrvinit.exe  
  
MD5：7415347d5ea5f0db29ec95a4a61aba90  
  
勒索修改后缀：L0CK3D  
  
加密算法：  
  
ChaCha20  
  
AES  
  
RC4  
  
勒索信文件：read-me3.txt  
  
勒索方式：多重勒索  
  
勒索网址：  
  
http://j3qxmk6g5sk3zw62i2yhjnwmhm55rfz47fdyfkhaithlpelfjdokdxad.onion/  
  
勒索信内容：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQWWZKAmRSrd8DxmEzX7D9LdeJbqsX9vATg02dVUUKysJxuUMfLYnmTQ/640?wx_fmt=png "")  
  
  
勒索页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQVdoIoTOCKeEDxKSI3WiaEPUs5ibrmpvU4MDyHgdicb0v3vtHXt4ZMpQ6g/640?wx_fmt=png "")  
  
  
**勒索软件功能：**  
  
勒索软件落地后，会首先创建互斥体：hsfjuukjzloqu28oajh727190。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQysWecynJr3Dc0kpO1ZiacApsCdwhgXzqyiaAgsTRqFXG0v83kxZYOlUg/640?wx_fmt=png "")  
  
  
而后会收集即时通信软件的各类配置信息，并尝试获取本地FTP与ＶＮＣ客户端软件的登录凭据。之后，软件还会检查当前系统中是否安装了压缩软件，并尝试获取浏览器历史记录与cookie密码，以及检查是否有安装邮件客户端。显然勒索软件打算以此来尽可能挖掘本地的各类通信数据内容。  
  
  
一切初始化与检查工作完成后，勒索软件便会对本地磁盘和网络共享中的文件进行加密，并同步向各个主要目录中释放勒索信文档。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JIs8JBpicTZaCHmHJjDFff3yAsias3aXqQfNwVj58AJc1NxDQia8L5JamXVyddE9ficDQVJ9dcZhbkFhNzHl8zlfIQ/640?wx_fmt=png "")  
  
  
  
一切完成后，软件还会删除系统中的磁盘卷影副本，来防止受害用户对被加密的数据进行回复。最终，勒索软件会删除自身来最大化地隐其形迹。  
  
  
**IOCs**  
  
  
-MD5  
  
7415347d5ea5f0db29ec95a4a61aba90  
  
-IP  
  
193.176.179.41  
  
193.43.72.11  
  
45.145.6.112  
  
193.43.72.11  
  
  
**360安全专家提醒**  
  
  
广大政企机构应建立全面的数字安全防御体系，下载安装360终端安全管理系统，以免重要数据泄露而产生不可逆的损失。  
  
  
**如需进一步咨询，******  
  
**请联系360安全专家：400-0309-360**  
  
往期推荐  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:0" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:0.td@@0" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;" width="100.0000%"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table width="100%"><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:0.td@@0:0.classicTable1:0" powered-by="xiumi.us"><td colspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:0.td@@0:0.classicTable1:0.td@@0" rowspan="2" style="border-color: rgb(62, 62, 62);border-style: none;background-position: 11.6747% 0%;background-repeat: no-repeat;background-size: 114.91%;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_jpg/pLEuriaaPnU0wbNshibhMK15JHCsgqEZzjg06ble0V2kWc84tnOAkb9icI8W6Nmq6ffPsBlmcWJzvACgjAiafAvtIA/640?wx_fmt=jpeg&#34;);padding: 0px;" width="30.0000%"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;" powered-by="xiumi.us"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 32px;line-height: 1;"><p><strong>01</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:0.td@@0:0.classicTable1:0.td@@1" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="color: rgb(140, 140, 140);line-height: 1;"><p style="text-wrap: wrap;"><span style="font-size: 12px;color: rgb(145, 196, 110);">● </span><span style="color: rgb(58, 66, 94);font-size: 15px;">ISC2023周鸿祎发布战略级产品360安全云，首提安全即服务</span></p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:0.td@@0:0.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:0.td@@0:0.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin: 10px 0%;" powered-by="xiumi.us"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;text-wrap: wrap;"><span style="color: rgb(208, 208, 208);">► <a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247563239&amp;idx=1&amp;sn=249e838ae2cf5f2a8570717d7f84a777&amp;chksm=9f8d67efa8faeef96fd676b8680a067989f945fbefa554acf09d141fb17e435573d801ddffd9&amp;scene=21#wechat_redirect" textvalue="点击阅读" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">点击阅读</a></span></p></section></section></td></tr></tbody></table></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:1.td@@0" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;" width="100.0000%"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table width="100%"><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:1.td@@0:0.classicTable1:0" powered-by="xiumi.us"><td colspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:1.td@@0:0.classicTable1:0.td@@0" rowspan="2" style="border-color: rgb(62, 62, 62);border-style: none;background-position: 50.4662% 0%;background-repeat: no-repeat;background-size: 155.188%;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_jpg/pLEuriaaPnU0wbNshibhMK15JHCsgqEZzjztA5jqtbFFFCcQqenFtC93mLXG0UiarTq8HE9qRPHG6ZL33nQiaef6rQ/640?wx_fmt=jpeg&#34;);padding: 0px;" width="30.0000%"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;" powered-by="xiumi.us"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 32px;line-height: 1;"><p><strong>02</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:1.td@@0:0.classicTable1:0.td@@1" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="color: rgb(140, 140, 140);line-height: 1;"><p style="text-wrap: wrap;"><span style="font-size: 12px;color: rgb(145, 196, 110);">● </span><span style="color: rgb(58, 66, 94);font-size: 15px;">打造企业数字安全中枢，360本地安全大脑上新安全协同处置平台</span></p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:1.td@@0:0.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:1.td@@0:0.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin: 10px 0%;" powered-by="xiumi.us"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;text-wrap: wrap;"><span style="color: rgb(208, 208, 208);">► <a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247567309&amp;idx=1&amp;sn=866a0ecf0e44298eec887f146f2b03a1&amp;chksm=9f8d57c5a8faded3bea3ab362eabb70138ebf2810588128d2da7aff9cd39cf42e2fedb79624d&amp;scene=21#wechat_redirect" textvalue="点击阅读" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">点击阅读</a></span></p></section></section></td></tr></tbody></table></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:2" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:2.td@@0" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;" width="100.0000%"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table width="100%"><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:2.td@@0:0.classicTable1:0" powered-by="xiumi.us"><td colspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:2.td@@0:0.classicTable1:0.td@@0" rowspan="2" style="border-color: rgb(62, 62, 62);border-style: none;background-position: 53.0668% 0%;background-repeat: no-repeat;background-size: 196.432%;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_jpg/pLEuriaaPnU0wbNshibhMK15JHCsgqEZzjOARiae383vEk0reeMaazpnBXveqFGhKPMFwXdfjyLaE7Eicu019ffv2g/640?wx_fmt=jpeg&#34;);padding: 0px;" width="30.0000%"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;" powered-by="xiumi.us"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 32px;line-height: 1;"><p><strong>03</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:2.td@@0:0.classicTable1:0.td@@1" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="color: rgb(140, 140, 140);line-height: 1;"><p style="text-wrap: wrap;"><span style="font-size: 12px;color: rgb(145, 196, 110);">●</span><span style="color: rgb(202, 29, 24);"> </span><span style="color: rgb(58, 66, 94);font-size: 15px;">360终端安全管理系统全新升级，助力构建大终端安全体系</span></p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:2.td@@0:0.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:2.td@@0:0.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin: 10px 0%;" powered-by="xiumi.us"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;text-wrap: wrap;"><span style="color: rgb(208, 208, 208);">► <a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247566698&amp;idx=1&amp;sn=c38468b25292d56412c15063df6d5a0d&amp;chksm=9f8d5562a8fadc74fc7d7065920e2a0ec789af72a7d28ffcc8e4c387ca9134d8814521acf990&amp;scene=21#wechat_redirect" textvalue="点击阅读" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">点击阅读</a></span></p></section></section></td></tr></tbody></table></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:3" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:3.td@@0" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;" width="100.0000%"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table width="100%"><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:3.td@@0:0.classicTable1:0" powered-by="xiumi.us"><td colspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:3.td@@0:0.classicTable1:0.td@@0" rowspan="2" style="border-color: rgb(62, 62, 62);border-style: none;background-position: 0% 32.9958%;background-repeat: no-repeat;background-size: 100%;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU0wbNshibhMK15JHCsgqEZzjXy1iaxgspdVpOiaXHBpQVYMvYN49dqsqDIm9SsYf1jVoqciaGmnOvOxNg/640?wx_fmt=png&#34;);padding: 0px;" width="30.0000%"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;" powered-by="xiumi.us"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 32px;line-height: 1;"><p><strong>04</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:3.td@@0:0.classicTable1:0.td@@1" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;" powered-by="xiumi.us"><section style="color: rgb(140, 140, 140);line-height: 1;"><p style="text-wrap: wrap;"><span style="font-size: 12px;color: rgb(145, 196, 110);">● </span><span style="color: rgb(58, 66, 94);font-size: 15px;">赛迪顾问：360领跑中国数字安全托管运营服务市场</span></p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:3.classicTable1:3.td@@0:0.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:3.classicTable1:3.td@@0:0.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);" width="70.0000%"><section style="margin: 10px 0%;" powered-by="xiumi.us"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;text-wrap: wrap;"><span style="color: rgb(208, 208, 208);">► <a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247566562&amp;idx=1&amp;sn=b5f0968bffb74d4bfdab245df5c60c2e&amp;chksm=9f8d54eaa8faddfc186215739040858bae451ac531542727a8e8a73ba07faa666126aa7b6552&amp;scene=21#wechat_redirect" textvalue="点击阅读" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">点击阅读</a></span></p></section></section></td></tr></tbody></table></section></section></td></tr></tbody></table>  
  
