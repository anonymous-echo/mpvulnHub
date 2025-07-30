#  JUNIPER NETWORKS修复了其防火墙和交换机中的一个关键远程代码执行(RCE)漏洞   
鹏鹏同学  黑猫安全   2024-01-13 11:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce81SmSkVYSGv45rmVBtZST843fMuaib6ibK9rHkpTpBpiarJp4TXPibkubez8xW8WaHaZ3EDDDpiayFyBg/640?wx_fmt=png&from=appmsg "")  
  
Juniper Networks发布了安全更新，以解决SRX系列防火墙和EX系列交换机中的一个关键的预身份验证远程代码执行（RCE）漏洞，该漏洞被标识为CVE-2024-21591。  
  
该漏洞存在于设备的J-Web配置界面中，未经身份验证的攻击者可以利用该漏洞获取root权限或对未修补的设备发起拒绝服务（DoS）攻击。  
  
厂商发布的公告中表示：“Juniper Networks Junos OS SRX系列和EX系列的J-Web中存在一种越界写入漏洞，允许未经身份验证的基于网络的攻击者导致拒绝服务（DoS），或者远程代码执行（RCE）并获取设备的root权限。这个问题是由于使用了一个不安全的函数，使得攻击者可以覆盖任意内存而引起的。”  
  
此漏洞影响Juniper Networks Junos OS SRX系列和EX系列：  
  
早于20.4R3-S9的Junos OS版本；早于21.2R3-S7的Junos OS 21.2版本；早于21.3R3-S5的Junos OS 21.3版本；早于21.4R3-S5的Junos OS 21.4版本；早于22.1R3-S4的Junos OS 22.1版本；早于22.2R3-S3的Junos OS 22.2版本；早于22.3R3-S2的Junos OS 22.3版本；早于22.4R2-S2、22.4R3的Junos OS 22.4版本。  
  
Juniper SIRT并未收到关于利用此漏洞的实际攻击报告  
。  
  
厂商发布了以下软件版本来解决此问题：Junos OS：20.4R3-S9、21.2R3-S7、21.3R3-S5、21.4R3-S5、22.1R3-S4、22.2R3-S3、22.3R3-S2、22.4R2-S2、22.4R3、23.2R1-S1、23.2R2、23.4R1及其后续版本。公告还包括一种解决方法，公司建议禁用J-Web，或仅限信任的主机访问。  
  
