#  漏洞通告 | aiohttp路径遍历漏洞   
原创 微步情报局  微步在线研究响应中心   2024-02-27 15:09  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**漏洞概况**  
  
  
  
aiohttp是一个用于异步网络编程的Python库，支持客户端和服务器端的网络通信。它利用Python的asyncio库来实现异步IO操作，这意味着它可以处理大量并发网络连接，而不会导致线程阻塞或性能下降。aiohttp常用于需要高性能网络通信的应用程序，如高频交易平台、大规模并发API服务等。  
  
微步漏洞团队通过“X 漏洞奖励计划”获取到aiohttp库路径遍历漏洞情报。  
  
经分析研判，该漏洞的利用条件为：  
1. 使用aiohttp实现Web服务；  
  
1. 配置aiohttp中的静态资源解析，使用了不安全的参数follow_symlinks，代码如routes.static("/static", static_dir, follow_symlinks=True)  
  
成功利用该漏洞可读取服务器上任意文件。  
另外值得一提的是，Github上多个高star开源项目并未正确配置该参数，目前已知受影响的开源项目有  
：  
- https://github.com/comfyanonymous/ComfyUI/  
  
- https://github.com/ray-project/ray  
  
综上所述，建议尽快自查是否使用了相关受影响的开源项目；如果使用了aiohttp实现Web服务，请结合上述分析排查是否使用错误配置。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：中**  
  
<table><tbody><tr style="height: 31.0667px;"><td width="133" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);word-break: break-all;"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞编号</span></strong><o:p></o:p></p></td><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">XVE-2024-1472</span><o:p></o:p></p></td></tr><tr style="height: 31.0667px;"><td width="133" colspan="1" rowspan="6" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞评估</span></strong><o:p></o:p></p></td><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">危害评级</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">中危</span><o:p></o:p></p></td></tr><tr style="height: 31.0667px;"><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞类型</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">路径遍历</span><o:p></o:p></p></td></tr><tr style="height: 27px;"><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">公开程度</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">PoC未公开</span><o:p></o:p></p></td></tr><tr style="height: 27px;"><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">无权限要求</span><o:p></o:p></p></td></tr><tr style="height: 27px;"><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">交互要求</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">0-click</span><o:p></o:p></p></td></tr><tr style="height: 27px;"><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">威胁类型</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">远程</span><o:p></o:p></p></td></tr><tr style="height: 27.2px;"><td width="133" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p></o:p></p></td><td width="187" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步已捕获攻击行为</span><o:p></o:p></p></td><td width="215" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">暂无</span><o:p></o:p></p></td></tr></tbody></table>#   
  
**漏洞影响范围**  
  
  
<table><tbody><tr style="height: 33.2px;"><td width="152" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);word-break: break-all;"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">产品名称</span></strong><o:p></o:p></p></td><td width="346" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">aiohttp</span><o:p></o:p></p></td></tr><tr style="height: 27px;"><td width="172" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">受影响版本</span></strong><o:p></o:p></p></td><td width="346" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">1.0.5 &lt; version &lt; 3.9.2</span><o:p></o:p></p></td></tr><tr style="height: 27px;"><td width="172" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">影响范围</span></strong><o:p></o:p></p></td><td width="346" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">十万级</span><o:p></o:p></p></td></tr><tr style="height: 35.6px;"><td width="172" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><strong><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有无修复补丁</span></strong><o:p></o:p></p></td><td width="346" colspan="1" rowspan="1" style="vertical-align: top;padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);"><p><span style="color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有</span><o:p></o:p></p></td></tr></tbody></table>  
  
前往X情报社区资产测绘查看影响资产详情：  
  
https://x.threatbook.com/v5/survey?q=app%3D"aiohttp"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKIKib8me7GwqIeXicyAWwjlaN8JxODmOoN3giat9Oa6QQJ1gFGo9LQiaQ9slP9dh8J7trE6zlIWiaRuTA/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞复现**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKIKib8me7GwqIeXicyAWwjlaKSZDFagH8ECY3SPT3aRRsIOcl1OAh2fCuqo3v4Y2EDgBJZ457ymVLA/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
##   
  
该项目已发布修复版本:   
https://github.com/aio-libs/aiohttp/releases/tag/v3.9.2  
  
## 临时修复方案：  
- 使用反向代理服务器（例如nginx）处理静态资源  
  
- 如果使用follow_symlinks=True，请立即禁用该选项  
  
- 使用防护类设备进行防护，拦截../../等路径穿越字符  
  
**微步产品侧支持情况**  
  
  
  
微步威胁感知平台TDP已支持检测，规则ID为：  
D120646e4f2，模型/规则高于20220102000000 可检出  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKIKib8me7GwqIeXicyAWwjlaPl4ibx97cxUR95ibWndEPzRM7iaaOyYQah0ib2Nq7ic9DH4OkzpnfqhhVyw/640?wx_fmt=png&from=appmsg "")  
  
  
**时间线**  
  
  
- 2023.01.19 微步"X漏洞奖励计划"获取该漏洞相关情报  
  
- 2024.02.26 微步发布报告  
  
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
  
  
  
