#  【安全圈】kkFileView文件上传代码执行漏洞   
 安全圈   2024-04-21 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
信息支援  
  
  
**一、漏洞****概述**  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;height: 20.15pt;visibility: visible;"><td width="78.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-width: 2.25pt 1.5pt 1.5pt 2.25pt;border-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">漏洞名称</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="365.3333333333333" colspan="3" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top-width: 2.25pt;border-top-color: windowtext;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;"><span style="outline: 0px;"> </span><span class="wx_search_keyword_wrap" style="outline: 0px;color: var(--weui-LINK);cursor: pointer;">kkFileView</span><span style="outline: 0px;">文件上传代码执行漏洞  </span></span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td></tr><tr style="outline: 0px;height: 20.15pt;visibility: visible;"><td width="98" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left-width: 2.25pt;border-left-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">CVE   ID</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="385.3333333333333" colspan="3" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-size: 14px;visibility: visible;">暂无</span></section></td></tr><tr style="outline: 0px;height: 20.15pt;visibility: visible;"><td width="98" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left-width: 2.25pt;border-left-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">漏洞类型</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="107.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: black;font-size: 14px;visibility: visible;"><span style="outline: 0px;">文件上传、RCE</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="103.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">发现时间</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">2024-04-17</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td></tr><tr style="outline: 0px;height: 20.15pt;visibility: visible;"><td width="98" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left-width: 2.25pt;border-left-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">漏洞评分</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">暂无</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="108.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">漏洞等级</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" height="20" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">高危</span><br style="outline: 0px;visibility: visible;"/><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td></tr><tr style="outline: 0px;visibility: visible;"><td width="98" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left-width: 2.25pt;border-left-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">攻击向量</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">网络</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="108.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">所需权限</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">无</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td></tr><tr style="outline: 0px;visibility: visible;"><td width="98" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left-width: 2.25pt;border-left-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">利用难度</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">低</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="108.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">用户交互</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 1.5pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;">无</span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td></tr><tr style="outline: 0px;visibility: visible;"><td width="98" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 2.25pt;border-bottom-color: windowtext;border-left-width: 2.25pt;border-left-color: windowtext;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;"><span style="outline: 0px;"><span class="wx_search_keyword_wrap" style="outline: 0px;color: var(--weui-LINK);cursor: pointer;">PoC</span><span style="outline: 0px;">/EXP</span></span><o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 2.25pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;">已公开<o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="108.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 1.5pt;border-right-color: windowtext;border-bottom-width: 2.25pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);font-size: 14px;visibility: visible;">在野利用<o:p style="outline: 0px;visibility: visible;"></o:p></span></section></td><td width="113.33333333333333" style="padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-top: none;border-right-width: 2.25pt;border-right-color: windowtext;border-bottom-width: 2.25pt;border-bottom-color: windowtext;border-left: none;background: rgb(222, 234, 246);visibility: visible;"><section style="outline: 0px;text-align: center;line-height: 25.5px;visibility: visible;"><span style="outline: 0px;font-size: 14px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);visibility: visible;">未知</span><span style="outline: 0px;font-family: 微软雅黑, &#34;sans-serif&#34;;color: rgb(51, 51, 51);visibility: visible;"><o:p style="outline: 0px;visibility: visible;"></o:p></span></span></section></td></tr></tbody></table>  
  
kkFileView是使用spring boot搭建的文档在线预览解决方案，能够支持多种主流办公文档的在线预览，如doc、docx、xls、xlsx、ppt、  
pptx  
、pdf、txt、zip、rar等格式。此外，它还可以预览图片、视频、音频等多种类型的文件。  
  
2024年4月17日，启明星辰  
VSRC  
监测到kkFileView中存在一个文件上传代码执行漏洞，目前该漏洞的细节及PoC/EXP已公开。  
  
kkFileView受影响版中的文件上传功能在处理压缩包时存在安全问题，威胁者可上传包含恶意代码的zip压缩包，覆盖系统文件，并可通过调用被覆盖的文件实现远程代码执行。  
  
  
## 二、漏洞复现  
  
****  
  
## 三、影响范围  
  
v4.2.0 <= kkFileView <= v4.4.0-beta  
## 四、安全措施  
### 4.1 升级版本  
  
目前官方暂未发布正式修复版本，但已在开发分支中修复，受影响用户可在修复版本可用时升级到修复版本。  
  
下载链接：  
  
https://github.com/kekingcn/kkFileView/releases  
### 4.2 临时措施  
  
开启 file.upload.disable=true参数，禁用首页的文件上传功能，关闭演示入口。  
  
若非必要，不将该系统暴露在公网，或可通过访问控制限制仅允许可信IP访问。  
### 4.3 通用建议  
  
定期更新  
系统补丁  
，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。  
  
加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
### 4.4 参考链接  
  
https://github.com/kekingcn/kkFileView/commit/421a2760d58ccaba4426b5e104938ca06cc49778  
  
https://github.com/kekingcn/kkFileView/issues/553  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljKXaHAiabApRD9oHyND5ztC4hNr4XPNvUZNyibH8RAIefyKEAmxkefufgMGoSXwU3EjgmHmiaibDGibuA/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】重磅！网络空间部队成立，筑牢国家网络边防](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058441&idx=1&sn=97568026e27f8b0053b57ff926b2ae15&chksm=f36e1f09c419961f1cdfdf7f210430167b6e974f900e5f2ed05b33587d9a0f0c7575ed1bd203&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljKXaHAiabApRD9oHyND5ztCHHL1b8wyh5BB3BibhV52cqiaxIz3X55BScYpiaXy3DTlnMzWpXXibDpY4Q/640?wx_fmt=png&from=appmsg "")  
[【安全圈】多个僵尸网络利用一年前的 TP-Link 漏洞进行路由器攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058441&idx=2&sn=d64040092e2636ebb14a8f9ff7cd36b3&chksm=f36e1f09c419961f8dd9875f7e0e28ce0a0908572600b95a77167950120e36d3353e6bcd13bb&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljKXaHAiabApRD9oHyND5ztCCqpd2QouRHDpVY2rLqIIJV4hqDjsRTDjPyoD82Zia1DFrUq7vYp0Dew/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】4TB 大小、210 万个文件，《严阵以待》游戏代码遭攻击泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058441&idx=3&sn=2ffe7e2bcc769351ee4c0dcaa1e17d65&chksm=f36e1f09c419961f0117715b7dd872239d59200fada61f997c89746b6616b428fa332e79e896&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljKXaHAiabApRD9oHyND5ztCbkn7fuOUF6axwGk2jW4LW1MrVVcrkibkoDbHRGS47reOVwUA81gTfdA/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】网络钓鱼即服务平台 LabHost 在全球范围内关闭](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058441&idx=4&sn=42584169680f82850e1559d807211ef3&chksm=f36e1f09c419961fd4019ecaef2ce40c99d617a02e2fafca6deba1af7e7e720ee2f5c0a854ef&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
  
