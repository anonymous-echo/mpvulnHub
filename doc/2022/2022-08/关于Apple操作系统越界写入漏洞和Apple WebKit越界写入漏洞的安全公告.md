#  关于Apple操作系统越界写入漏洞和Apple WebKit越界写入漏洞的安全公告   
原创 CNVD  CNVD漏洞平台   2022-08-21 17:52  
  
**安全公告编号:CNTA-2022-0021**  
  
2022年8月21日，国家信息安全漏洞共享平台（CNVD）收录了Apple操作系统越界写入漏洞（CNVD-2022-58457，对应CVE-2022-32894）和Apple WebKit越界写入漏洞（CNVD-2022-58458，对应CVE-2022-32893）。目前苹果公司已发布更新版本修复上述漏洞，CNVD建议受影响用户及时升级到最新版本。  
  
**一、漏洞情况分析**  
  
iOS是由苹果公司开发的移动操作系统，iPadOS是苹果公司基于IOS开发的移动端操作系统，Mac OS是苹果开发的运行于Macintosh系列的操作系统，WebKit是Safari和其他在iOS和iPadOS上浏览器的引擎。  
  
2022年8月17日，苹果公司紧急发布iOS 15.6.1、iPadOS 15.6.1与macOS Monterey 12.5.1的安全更新，修复了Apple操作系统越界写入漏洞和Apple WebKit越界写入漏洞。  
由于iOS15和Monterey ma  
cOS边界检查不完全导致存在越界写入缺陷，攻击者可利用该漏洞进行提权操作，以内核权限实现任意代码执行。  
由于WebKit边界检查不完全导致存在越界写入缺陷，攻击者可利用该漏洞诱骗用户访问包含恶意代码的网站，从而实现任意代码执行。  
  
CNVD对上述漏洞的综合评级为“高危”。  
  
**二、漏洞影响范围**  
  
漏洞影响的产品版本包括：  
  
运行iOS 15的设备版本<15.6.1  
  
运行iPadOS 15的设备版本<15.6.1  
  
运行macOS
Monterey的设备版本<12.5.1  
  
Apple Safari浏览器版本<15.6.1  
  
以下是受影响的设备：  
  
运行 macOS
Monterey 的 Mac 设备  
  
iPhone 6s 及后续推出的机型  
  
iPad Pro 所有机型  
  
iPad Air 2 及后续推出的机型  
  
第五代 iPad 及后续机型  
  
iPad mini 4 及后续机型  
  
iPod Touch 第七代  
  
**三、漏洞处置建议**  
  
目前，苹果公司已发布更新版本修复上述漏洞，CNVD建议受影响用户立即升级至最新版本：  
  
https://support.apple.com/zh-cn/HT201222  
  
附参考链接：  
  
https://support.apple.com/zh-cn/HT201222  
