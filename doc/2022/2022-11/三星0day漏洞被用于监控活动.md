#  三星0day漏洞被用于监控活动   
ang010ela  嘶吼专业版   2022-11-11 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
谷歌Project Zero研究人员发现有攻击者利用三星手机多个0day漏洞用于监控活动。  
  
近日，谷歌Project Zero研究人员披露了三个三星手机0 day漏洞被监控公司用于监控活动，漏洞CVE编号为CVE-2021-25337、CVE-2021-25369、CVE-2021-25370：  
  
CVE-2021-25337：该漏洞为三星手机设备剪贴板服务访问控制不当的问题，攻击者利用该漏洞可以让不可信的应用读写特定本地文件；  
  
CVE-2021-25369：该漏洞为sec_log文件的访问控制不当问题，会将敏感kernel信息暴露给用户空间；  
  
CVE-2021-25370：该漏洞是dpu驱动中处理文件描述符的错误实现导致的，会引发内存破坏最终导致影响kernel。  
  
谷歌研究人员指出监控公司使用的监控软件在利用这3个漏洞时漏洞尚未发布补丁，因此属于0 day漏洞。  
  
该漏洞利用链是一个典型的不同攻击面的例子。漏洞利用链中的3个漏洞都位于设备厂商组件中，而非AOSP平台或Linux kernel中。而且其中2个漏洞都是逻辑和设计漏洞，而非内存安全漏洞。  
  
研究人员分析认为，漏洞利用样本攻击的是运行kernel 4.14.113（Exynos SOC）的三星手机。而使用这种SOC的手机主要在欧洲和非洲销售。漏洞利用依赖的Mail GPU驱动和DPU驱动，都是针对基于Exynos的三星手机。  
  
受影响的三星手机包括S10、A50、A51等。谷歌称这3个漏洞已于2021年3月被三星修复。  
  
谷歌在安全公告中并未指出利用这3个三星手机漏洞进行监控的厂商名，但强调与其他攻击意大利和哈萨克斯坦安卓用户的攻击活动有相似之处。  
  
由于三星在发布漏洞补丁时未说明漏洞利用的情况，因此建议使用相关设备的用户尽快检查是否安装补丁。  
  
参考及来源：https://securityaffairs.co/wordpress/138302/hacking/surveillance-vendor-exploited-samsung-phone-zero-days.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icicZgjAfeuUpqfbYYlEqWD2yKS6xK2QCicEDKgaicsDWhBsX8Uu2QDRpmLAkUoiawCu74Wtd9mU2s1wg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icicZgjAfeuUpqfbYYlEqWD2icwTaIE88HFq34ibb8D11BAIWHzWOCky6Fc3lcng5dhgDzDPgRhyx66Q/640?wx_fmt=png "")  
  
  
