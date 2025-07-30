> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAwMDQwNTE5MA==&mid=2650247775&idx=1&sn=0a851ba2205a3466f75d593c4698f5fe

#  威胁情报 | Confucius 组织最新组件化后门 anondoor 披露  
 白帽子   2025-06-20 10:11  
  
**作****者：知道创宇404高级威胁情报团队**  
  
  
**1.背景**  
  
  
参考资料  
### 1.1 组织介绍  
  
Confucius组织（又称“魔罗桫”）于2016年被国外安全厂商披露，据悉最初的攻击活动可追溯到2013年。该组织主要针对南亚及东亚地区政府、军事等重要单位，近年来不断发现针对国内重点单位及行业发起攻击活动。  
### 1.2 概述  
  
近期，知道创宇404高级威胁情报团队发现了Confucius组织的新的武器，该武器不仅加载了2024年利用ADS攻击时的wooperstealer[1]，还将其前一阶段的下载者木马升级为组件化的后门。后门组件均通过服务端下发的链接下载而来。为方便后续描述，使用代码中的特殊字符串"anon"将其命名为"anondoor"。  
### 1.3 核心发现  
  
**1、持久化操作从初始阶段脚本转移到anondoor**  
  
此前捕获的Confucius的攻击样本中，通常在初始的脚本中进行持久化，例如在LNK脚本中写入自启动注册表项或者远程下载脚本中写入注册表项中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72KhUe5eP39gLpgxBRmd9kyl6gjQxSicIPpvM7A7dibZKkzsZzmWicgA4Nw/640?wx_fmt=png&from=appmsg "")  
  
而本次样本则在下载者木马中进行持久化，详见后续分析。  
  
**2、wooperstealer作为组件，通信地址通过anondoor参数传入**  
  
本次捕获的样本最终下载组件为wooperstealer，但组件本身无窃密文件回传的服务端地址，通过前一阶段(anondoor)加载时传入。  
  
**3、下载者升级为组件化后门**  
  
攻击者将此前多次使用的downloader木马进行了升级，添加了后续载荷下载地址的服务端分发逻辑，并新增了多项后门功能，所有功能均需要从服务端下载相应的组件来实现，详见后续分析。  
  
  
**2. 样本分析**  
  
  
参考资料  
  
初始样本为LNK文件，Lnk参数中的脚本下载多个文件，其中python313.dll为anondoor，BlueAle.exe为白文件(实际为python官方程序pythonw.exe)，当BlueAle.exe运行时，anondoor将被加载运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72MMgzkEPbXKPGibe71TzVCfVDISh9SiaIcuNbAfzXuDeu0y4ibEzGNhTRQ/640?wx_fmt=png&from=appmsg "")  
### 2.1 持久化  
  
将BlueAle.exe写入名为"SystemCheck"的计划任务中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72LTmGFDmTXvfaBZavRUXs0Oxt2UNviaBm9eicUickoiagKlG2aTNQLsqpdQ/640?wx_fmt=png&from=appmsg "")  
### 2.2 系统信息回传  
  
获取主机系统版本、本地IP、主机名、公网IP和IP归属地，将获取的信息拼接上
```
uhhg
```

  
和
```
$!!$
```

  
后发送到服务端：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72ibYW0wMXEWTWho6EDiaXRLHt6FafiaqdUrofDrMqp4sDcazZrQCvJQicaw/640?wx_fmt=png&from=appmsg "")  
  
其中UUID通过获取系统固件信息（ACPI表），并尝试提取前16字节返回后拼接上主机名和用户名，最终使用自定义的hash算法生成代表受控主机的UUID，该值在后续多处均有使用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72YhXcUX5G8nO22OsIIxVZO48OjproUCKgS07S7kBRdwnCsTbdpkIaRw/640?wx_fmt=png&from=appmsg "")  
  
获取磁盘盘符及大小后发送到服务端：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ726JatibD4EwFpLqtxFcwseGibdBqRiahmZxXPeQLLd7GeVX6qOg2yERaBg/640?wx_fmt=png&from=appmsg "")  
### 2.3 wooperstealer组件下载  
  
发送如下格式内容到服务端获取后续组件的下载地址：  
  

```
autonbfgj=base64-encode(%UUID%+&#34;[@]AutoDownload[@]&#34;)
```

  
  
若返回的数据为"Somethingworng1-"，则进行下一次请求，不是则进行后续的交互逻辑：  
  
将返回的数据使用“@#@”进行分割成4个block：  
  
block1：UUID  
  
block2：固定字符串"AutoDownload"  
  
block3：下载地址相关  
  
block4：组件控制指令  
  
再对block3使用“###”进行分割，其中第2块数据则为实际的组件下载地址（记为block3-2），若block4为“start”则请求block3-2中地址并加载运行，若为“stop”则中止组件运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72kfTmIWiaWpYibLGPKdsLSDibzNoiaw35H2pWhAcAFVl2Lr315GqX6y3JbQ/640?wx_fmt=png&from=appmsg "")  
  
用
```
$@!!@$
```

  
按照以下顺序拼接数据：  
  

```
block1 + block2 + block3 + block3-2 + C2 + C2_URL + userAgent + port + requestFlags
```

  
  
请求block3-2下载组件后，加载其“Yretisdkjhsfkjfh”方法运行，并将上述拼接数据作为参数传入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72RPaI6rEBgny8uZdpL78RvRiaOoic4iaHqXwTPjibXicRdhQRe6mZKf47FjA/640?wx_fmt=png&from=appmsg "")  
  
值得注意的是，下载的组件为此前曾曝光的wooperstealer，其功能无重大变化，在此不再赘述。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72uvQ05dWqFGIHwTsvibicn7qKP1VuVZwSUxYKa3QKB8ZxJJbPMFR04iaJg/640?wx_fmt=png&from=appmsg "")  
### 2.4 anondoor核心功能  
  
获取后门指令的请求格式如下：  
  

```
cuud=base64_encode(%UUID% + &#34;$!!$khfgsh&#34;)
```

  
  
当服务端下发指令后，anondoor还会将指令按照如下格式进行返回：  
  

```
sout=%UUID% + &#34;@$$@&#34; + command
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72Bum2qicdHbEibBXdTuPJAsKf8Gvd5IObHiaukoFyWPibJururpauNP3Nvw/640?wx_fmt=png&from=appmsg "")  
  
最终解析返回的指令，其格式大致如下：  
  

```
%module_id% #$$ %commandType% #$$ %base64_str% ###  %command% ###  %url%
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72Bz2hib6vVCjZ40yhiankofLlIGpgSOfvickB4M1E9zEJmsficL48ib74pgA/640?wx_fmt=png&from=appmsg "")  
  
其中“module_id”疑为组件的id，url则是对应后门功能的组件下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72WiaLEfHTaLN10F2v4KkvM2afWHyjKyEhCJS0rX6zj6yOXC1tBkKxSIg/640?wx_fmt=png&from=appmsg "")  
  
所支持的指令如下表：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT1bd2DYia7v6kbgGTCkWEQ72orjJ1J66yoicCxlOlQ47dTyTedtiabfdfImaibZuwJcnxa0Zp8En3h3EA/640?wx_fmt=png&from=appmsg "")  
  
所有组件的通信地址均是通过anondoor参数传递，且需要加载指定的方法，这直接导致了众多沙箱无法加载运行，目前杀软查杀为0。  
  
  
**3. 总结**  
  
  
参考资料  
  
  
Confucius组织近年来对周边国家的攻击频繁发生，攻击手段不断升级，从此前曝光的下载执行单一窃密木马演变为模块化后门，展现出较高的技术迭代能力。其后门组件采用C# DLL文件封装，通过invoke加载指定方法来规避沙箱检测；同时，利用参数化的C2（命令与控制）通信机制，确保即使部分组件被捕获，攻击者仍能隐藏真实的C2基础设施，极大增加了溯源和防御难度。  
  
  
**4. IOC**  
  
  
参考资料  
  
  
**HASH：**  
  
abefd29c85d69f35f3cf8f5e6a2be76834416cc43d87d1f6643470b359ed4b1b  
  
  
**5. 参考链接**  
  
  
参考资料  
  
  
1、  
https://paper.seebug.org/3230/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT0Z79Hq9GCticVica4ufkjk5xiarRicG97E3oEcibNSrgdGSsdicWibkc8ycazhQiaA81j3o0cvzR5x4kRIcQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**往 期 热 门******  
  
(点击图片跳转）  
  
[](https://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650990928&idx=1&sn=3dd0d8b72b8baf68205bfbcb35900598&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650990921&idx=1&sn=357192c6954ccc6d97f28e848414485b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650990896&idx=1&sn=1071355115ff502f3968391dcd234fac&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT3XlD8Odz1EaR5icjZWy3jb8ZZPdfjQiakDHOiclbpjhvaR2icn265LYMpu3CmR1GoX707tWhAVsMJrrQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
戳  
“阅读原文”  
更多精彩内容  
!  
  
  
