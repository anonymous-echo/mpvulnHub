#  漏洞通告 | 通天星CMSV6车载定位监控平台系列漏洞   
原创 微步情报局  微步在线研究响应中心   2024-03-15 11:31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
通天星CMSV6车载定位监控平台拥有以位置服务、无线3G/4G视频传输、云存储服务为核心的研发团队，专注于为定位、无线视频终端产品提供平台服务，通天星CMSV6产品覆盖车载录像机  
、单兵  
录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。  
  
微步漏洞团队通过“X 漏洞奖励计划”获取到通天星CMSV6车载定位监控平台SQL注入漏洞情报（XVE-2023-23744）和通天星CMSV6车载定位监控平台任意文件上传漏洞情报（XVE-2023-23454）。  
  
值得一提的是，由于该系统在默认配置下并未配置secure_file_priv，所以攻击者可以利用XVE-2023-23744任意读取和写入文件，从而进一步获取服务器权限。**综上所述，该系列漏洞利用难度低，造成危害大，建议用户尽快修复该漏洞。**  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：**  
**高**  
  
****<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 31.0667px;"><td width="133" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞编号</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">XVE-2023-23744</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="133" colspan="1" rowspan="6" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞评估</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">危害评级</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">高危</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞类型</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">SQL注入 to RCE</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">公开程度</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">PoC未公开</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无权限要求</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">交互要求</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">0-click</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">威胁类型</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程</span></td></tr><tr style="outline: 0px;height: 27.2px;"><td width="133" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步已捕获攻击行为</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">暂无<br/></span></td></tr></tbody></table>#   
  
**综合处置优先级：**  
**高**  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 31.0667px;"><td width="133" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞编号</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">XVE-2023-23454</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="133" colspan="1" rowspan="6" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞评估</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">危害评级</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">高危</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">漏洞类型</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">文件上传</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">公开程度</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">PoC未公开</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无权限要求</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">交互要求</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">0-click</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">威胁类型</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程</span></td></tr><tr style="outline: 0px;height: 27.2px;"><td width="133" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="187" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步已捕获攻击行为</span><o:p style="outline: 0px;"></o:p></p></td><td width="215" colspan="1" rowspan="1" style="padding: 0px 7.2px;border-width: 0.666667px;border-color: rgb(191, 191, 191);outline: 0px;word-break: break-all;hyphens: auto;vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">暂无<br/></span></td></tr></tbody></table>#   
  
**漏洞影响范围**  
  
  
  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 33.2px;"><td width="152" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">产品名称</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">通天星CMSV6车载定位监控平台</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">受影响版本</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">version &lt; 7.33.0.2_20240305</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">影响范围</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">千级</span></td></tr><tr style="outline: 0px;height: 35.6px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有无修复补丁</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">有</span></td></tr></tbody></table>  
  
前往X情报社区资产测绘查看影响资产详情：https://x.threatbook.com/v5/survey?q=app="通天星CMSV6车载定位监控平台"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFDsU90l3j1nFc1pBTH8XxS7HfJXZNlS8CbeDXccZFDFzo9o5eMevgiciaw/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞复现**  
  
  
  
- XVE-2023-23744  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFDxqbpVDAONyiaQRQa25LBKvyibbtRz0LApibc1rBuzYiaA16iaaBB8bUSdNg/640?wx_fmt=png&from=appmsg "")  
- XVE-2023-23454  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFDBIW6ADXBic9mNNEFFF4txib4aibm4s2AcbxWKThfmE9jIYdNhib59Qe8Sg/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
**官方修复方案：**  
  
厂商已发布漏洞修复程序，请前往以下地址下载  
  
http://www.g-sky.cn/list-70-1.html  
  
## 临时修复方案：  
- 使用防护类设备对相关资产进行防护  
  
- 如非必要，避免将资产暴露在互联网  
  
**微步产品侧支持情况**  
  
  
  
**微步威胁感知平台TDP已支持检测**  
  
- XVE-2023-23744，TDP规则ID：S3100125051，模型/规则高于20230810000000可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFDgTp3ZAu7urBiamTfjGNPGdzZ2vcVckQeIJP3mtVAcQibkibyrbwLjzVDQ/640?wx_fmt=png&from=appmsg "")  
- XVE-2023-23454，TDP规则ID：S3100123192、S3100123193，模型/规则高于20230808000000可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFD54YpyQdVnwn5sAJr6j42hgKmMaz9pob8zWTBVKN51gbgE0WqXnr0YQ/640?wx_fmt=png&from=appmsg "")  
  
**微步安全情报网关OneSIG已支持防护**  
- XVE-2023-23744，SIG规则ID：3100125051  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFD6IicG00Vzma0fr9qveWw7CAAvob1SCib5vVR2aMM7K3t4UdgsAZ86UtA/640?wx_fmt=png&from=appmsg "")  
- XVE-2023-23454，SIG规则ID：3100123192  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFDExibBypibOibal3rfghFqV8MYyJR1jSTxJ5KyySuM4Lo12BMoEFaN9j1w/640?wx_fmt=png&from=appmsg "")  
  
  
**时间线**  
  
  
- 2023.08.09 微步"X漏洞奖励计划"获取该漏洞相关情报  
  
- 2023.08.20   
TDP和OneSIG支持检测和防护  
  
- 2024.03.05 厂商发布补丁  
  
- 2024.03.15 微步发布报告  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Yv6ic9zgr5hSjF5ugwo1dgibkJbx9quORvic1Jd3cbE6HTJcib0K3hVSYpChOHM4OsFcibNib1G4qfCVrglZ348Oebkg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1 "")  
  
网安人不容错过的年度盛会——CSOP 2024 正在火热报名中，只有干货，席位紧俏。扫码立即报名北京站大会 ↓  
↓  
↓  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/fFyp1gWjicMLC7CEC8tqZ3Q8syMZ8lwFDe5oyjKZ3ZiaGQMTkThBYwib3VJAx0kibCzUBSDUygqkHIMj1oJSnEcicxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
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
  
  
  
