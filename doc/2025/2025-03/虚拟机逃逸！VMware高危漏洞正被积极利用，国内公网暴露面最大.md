#  虚拟机逃逸！VMware高危漏洞正被积极利用，国内公网暴露面最大   
​安全内参  商密君   2025-03-07 23:56  
  
**VMware虚拟机逃逸漏洞正被积极利用，据统计全球近4万台服务器存风险，其中中国、法国、美国的受影响服务器数量位列前三，中国约4400台服务器存在风险。**  
  
  
3月7日消息，超过3.7万台暴露在互联网上的VMware ESXi实例易受CVE-2025-22224漏洞的影响。该漏洞是一个高危级别的越界写入漏洞，目前正在被积极利用。  
  
威胁监测平台The Shadowserver Foundation披露了这一大规模暴露情况。  
  
3月5日，该平台统计的受影响实例数量约为41500台。次日，Shadowserver报告称，仍有3.7万台服务器存在漏洞，这表明5日有4500台设备完成修补。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7v7O0JTCkH6M6zIBALoOicG85d4VoSBRxCY04B7C7HqCRpTP1E8gEwBMQzPgNmibxG5qoAVmagurrHQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
CVE-2025-22224是一个高危级别的VCMI堆溢出漏洞  
，允许本地攻击者在拥有虚拟机客户机（VM Guest）管理员权限的情况下，逃离沙盒并以VMX进程的身份在宿主机（Host）上执行代码。  
  
3月4日，VMware母公司博通向客户发布警告，指出该漏洞以及另外两个漏洞（CVE-2025-22225和CVE-2025-22226）已被攻击者作为零日漏洞利用。  
  
这些漏洞由微软威胁情报中心发现，但该机构并未公布观察到的攻击时间，攻击来源和目标目前也未被披露。  
  
美国网络安全和基础设施安全局（CISA）已要求，联邦机构和州级组织必须在3月25日之前（3周内）部署可用的更新和缓解措施，否则必须停止使用该产品。  
  
Shadowserver报告指出，大多数受影响实例位于中国（4400台），其次是法国（4100台）、美国（3800台）、德国（2800台）、伊朗（2800台）、巴西（2200台）。  
  
然而，由于VMware ESXi在企业IT环境中被广泛用于虚拟机管理，其影响具有全球性。  
  
关于CVE-2025-22224的修复方案，建议用户查看博通官方公告，以获取受影响ESXi版本的详细信息。目前，该漏洞尚无可行的变通方案。  
  
此外，供应商还发布了常见问题（FAQ）页面，供用户了解进一步的行动建议及漏洞影响详情。  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：安全内参  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
