#  可任意文件读取，警惕Solr身份绕过形成的漏洞利用链   
原创 微步情报局  微步在线研究响应中心   2024-10-30 11:40  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
Apache Solr是一个基于Apache Lucene的开源企业搜索平台。它提供快速可靠的搜索，分布式索引，复制和负载平衡查询，自动故障转移和恢复，集中化配置以及其他功能。  
  
微步情报局于近日获取到Apache Solr 身份认证绕过漏洞情报（https://x.threatbook.com/v5/vul/XVE-2024-29630，CVE编号CVE-2024-45216）。在  
以集群模式启动的Solr实例中  
，攻击者能够通过在任何Solr URL API 路径的末尾  
添加一个伪造的路由，绕过身份认证机制，访问任意API  
。  
  
由于此漏洞影响版本范围较广，所以  
可结合Solr历史漏洞形成组合利用链。微步情报局已实现任意文件读取的组合利用，目前不排除可结合其他漏洞实现RCE  
。  
  
该漏洞利用较为简单且 PoC 已公开，建议尽快修复。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 31.0667px;"><td width="110" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><strong style="outline: 0px;">基本信息</strong></span><o:p style="outline: 0px;"></o:p></p></td><td width="186" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">XVE-2024-29630</span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td colspan="1" rowspan="1" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">漏洞类型</span><br style="outline: 0px;"/></td><td colspan="1" rowspan="1" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="font-size: 14px;color: rgb(84, 84, 84);">身份鉴别错误</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="135" colspan="1" rowspan="5" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件评估</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用漏洞的网络条件<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">是否需要绕过安全机制</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">对被攻击系统的要求<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(219, 0, 0);">以集群方式启动Solr</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;text-wrap: wrap;">利用漏洞的权限要求</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无需任何权限</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">是否需要受害者配合</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27.2px;"><td width="115" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">POC是否公开</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">是<br/></span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td colspan="1" rowspan="1" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">已知利用行为<br style="outline: 0px;"/></span></td><td colspan="1" rowspan="1" width="222" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="font-size: 14px;color: rgb(84, 84, 84);">否<br/></span></td></tr></tbody></table>#   
  
**漏洞影响范围**  
  
  
  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 33.2px;"><td width="152" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">产品名称</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">Apache软件基金会 - Apache Solr</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">受影响版本</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span style="font-size: 14px;color: rgb(84, 84, 84);">5.3.0 ≤ version &lt; 8.11.4</span></p><p><span style="font-size: 14px;letter-spacing: 0.578px;color: rgb(84, 84, 84);">9.0.0 ≤ version &lt; 9.7.0</span></p></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">影响范围</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">万级</span></td></tr><tr style="outline: 0px;height: 35.6px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有无修复补丁</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">有<br/></span></td></tr></tbody></table>  
  
前往X情报社区资产测绘查看影响资产详情：  
  
https://x.threatbook.com/v5/survey?q=app%3D%22solr%22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLwp5eBIVgfZHMicVu1wDPOAe0Rlia8KGZvbGVrXWIib9SnPfAhibhia70XG21eUNoQV5ECG9YnI5RbZmQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLwp5eBIVgfZHMicVu1wDPOAn4X7XUha1iaxono9tcia9AsyibjSkQFuctCMibvOu7QYALxjW9FjX2mib0g/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
厂商已修复此漏洞，可通过以下链接下载最新版本：  
  
https://solr.apache.org/security.html#cve-2024-45216-apache-solr-authentication-bypass-possible-using-a-fake-url-path-ending  
  
## 临时修复方案：  
- 避免将Solr实例暴露于互联网上  
  
- 使用防护类设备进行防护，拦截URL中带有 “:/admin/info/key” 特征的请求  
  
  
**微步产品侧支持情况**  
  
  
  
微步威胁感知平台TDP已支持检测，检测ID为S3100156199 ，模型/规则高于20241030000000 可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLwp5eBIVgfZHMicVu1wDPOAXBltRwPCBXmAfHDt9yTHK5K0HxC4yuNicKwodGYBaiaibWVhAVCqPicbjQ/640?wx_fmt=png&from=appmsg "")  
  
  
- END -  
  
  
  //    
  
**微步漏洞情报订阅服务**  
  
  
微步提供漏洞情报订阅服务，精准、高效助力企业漏洞运营：  
- 提供高价值漏洞情报，具备及时、准确、全面和可操作性，帮助企业高效应对漏洞应急与日常运营难题；  
  
- 可实现对高威胁漏洞提前掌握，以最快的效率解决信息差问题，缩短漏洞运营MTTR；  
  
- 提供漏洞完整的技术细节，更贴近用户漏洞处置的落地；  
  
- 将漏洞与威胁事件库、APT组织和黑产团伙攻击大数据、网络空间测绘等结合，对漏洞的实际风险进行持续动态更新。  
  
  
扫码在线沟通  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
  
  
