#  手把手玩转路由器漏洞挖掘系列 - COAP协议分析   
原创 nil  山石网科安全技术研究院   2024-05-23 15:17  
  
##  1. 基本介绍   
### 1.1 概要 - 轻量化HTTP协议  
  
CoAP（Constrained Application Protocol）是一种专为受限环境下的物联网设备设计的轻量级通信协议。它基于UDP协议，旨在提供一种简单、高效的通信方式，适用于资源受限的设备和低带宽网络环境。CoAP遵循RESTful架构风格，使用类似HTTP的方法（GET、POST、PUT、DELETE）来进行资源的操作，每个资源都有一个唯一的标识符（URI）。  
- 端口  
  
5684 - NoSec  
  
5684 - DTLS  
  
### 1.2 消息内容  
- 请求消息、响应消息  
  
- 消息类型、方法代码、消息ID、Token、选项、负载字段  
  
### 1.3 建立过程  
- 客户端发起请求 - 建立CoAP通信的第一步是客户端向服务器发起请求。客户端创建一个CoAP请求消息，包括请求方法（GET、POST、PUT、DELETE）、目标URI和其他必要的选项。  
  
- 消息传输 - CoAP消息可以使用两种类型的传输方式：CON（Confirmable）和NON（Non-Confirmable）。CON消息需要进行可靠传输，包括消息重传和确认机制；而NON消息是不可靠传输，不需要确认。  
  
- 服务器响应 - 服务器接收到客户端的请求后，根据请求内容进行处理，并生成一个对应的响应消息。响应消息包括响应码、选项和可能的负载数据。  
  
- 消息传输确认 - 如果客户端发送的是CON消息，服务器在接收到请求后需要发送一个确认消息（ACK）给客户端。客户端收到确认后，可以继续发送下一个请求或者处理服务器的响应。  
  
- 处理观察请求 - 如果客户端请求中包含观察选项，服务器可以在资源状态发生变化时向观察者发送通知消息，以更新客户端的状态。  
  
- 安全传输 - 为了保证通信的安全性，CoAP可以使用基于DTLS（Datagram Transport Layer Security）的安全传输机制，对通信内容进行加密和认证。  
  
### 1.4 协议报文  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRot8KrlqTehEibx8bg2Z5JAN8sqKCcUbwXhT2LFDYMGky7MiaVkposUN8frWA25vQ2Yuzn8w4m3PzQ/640?wx_fmt=png&from=appmsg "")  
  
消息头部  
- **版本（Version）**：CoAP协议的版本号，通常为1。  
  
- **类型（Type）**：消息类型，包括CON（Confirmable）、NON（Non-Confirmable）、ACK（Acknowledgement）和 RST（Reset）。  
  
- **Token**：用于标识请求和响应之间的关联，防止重放攻击。  
  
- **消息代码（Code）**：指定消息的类型和操作，如请求方法（GET、POST、PUT、DELETE）或响应状态码。  
  
- **消息ID（Message ID）**：用于标识消息的唯一ID，用于匹配请求和响应。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRot8KrlqTehEibx8bg2Z5JAjSH5r0MMicuXPdtnziaJh90woQtjv6IicS5Pzkb7FfdULlTPKql7zYEtA/640?wx_fmt=png&from=appmsg "")  
  
选项  
- **URI路径（URI-Path）**：指定资源的路径。  
  
- **观察（Observe）**：用于观察资源状态变化的选项。  
  
- **内容格式（Content-Format）**：指定消息的内容格式，如JSON、XML等。  
  
- **最大传输单元（Max-Age）**：指定资源的最大缓存时间。  
  
负载  
- **Payload:** CoAP消息可以包含负载数据，用于传输实际的应用数据。  
  
实例  
  
请求消息  
```
Type: CON
Code: GET
Message ID: 12345
Token: 0x4D
URI-Path: /resource
```  
  
响应消息  
```
Type: ACK
Code: 2.05 Content
Message ID: 12345
Token: 0x4D
Content-Format: application/json
Payload: {"key": "value"}
```  
##  2. 安全风险   
- 缺乏加密机制  
  
CoAP本身并没有提供对通信内容的加密机制，因此在传输过程中可能会受到窃听和篡改的风险。为了确保通信的机密性和完整性，需要额外的安全机制，如基于DTLS的加密传输。  
- 重放攻击  
  
由于CoAP消息中包含Token用于标识请求和响应之间的关联，但如果未正确实现Token的管理和验证，可能会导致重放攻击，攻击者可以重复发送已捕获的有效消息，从而误导服务器执行重复操作。  
- 拒绝服务  
  
攻击者可以利用CoAP协议的特点，发送大量的请求消息给服务器，消耗服务器资源，导致服务不可用。特别是在资源受限的设备上，可能更容易受到DoS攻击的影响。  
- 未授权访问  
  
由于CoAP消息是基于UDP传输的，因此可能容易受到IP地址欺骗等攻击，导致未经授权的设备访问资源或执行操作。  
- 安全选项缺失  
  
有些实现可能缺少对CoAP安全选项的支持，如观察选项和安全传输选项，这可能导致信息泄露或未经授权的资源访问。  
##  3. 攻击利用   
  
公网公开SOAP协议端口设备数量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRot8KrlqTehEibx8bg2Z5JAibnjVE0ZB9hOsuD0pRctt6ftKYJf3tVlORcGjvG6BLaG9iaAYTE1plFw/640?wx_fmt=png&from=appmsg "")  
### 3.1 /.well-known/core  
  
CoAP服务器中一般包括一个事先约定的路由（/.well-known/core）。/.well-known/core是CoRE（Constrained RESTful Environments）规范中定义的一种资源发现机制，用于在物联网环境中发现和描述可用的资源,该机制允许客户端通过向特定URI发送请求来获取服务器上可用资源的列表和相关信息。  
  
某台设备获取响应数据报文  
```
Version: 1
Type: Acknowledgement
TokenLength: 0
Code: Content
MessageId: 32053

\x02\xff\xff\xffThis is a test server made with libcoap (see http://libcoap.sf.net)
Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>




CoAP Resources:

:`E/l\xc1(\xff</>;title="General Info";ct=0
</qlink/searchfh>;title=qlink/searchfh
</qlink/searchgw>;title=qlink/searchgw
</qlink/request>;title=qlink/request
</qlink/success>;title=qlink/success
</device/inform/bootstrap>;title=device/inform/bootstrap
</device/inform/boot>;title=device/inform/boot
</device/inform/syncreq>;title=device/inform/syncreq
</device/inform/offline>;title=device/inform/offline
</device/inform/heartbeat>;title=device/inform/heartbeat
</device/inform/data>;title=device/inform/data
</async>;ct=0
```  
### 3.2 拒绝服务攻击  
  
对反射源发送伪造的数据包，反射源向受害者IP响应的流量远超过攻击者伪造UDP流量的数据，依靠此方式对受害者实施DDoS攻击。  
  
利用UDP的传输方式，发送该字符串到指定目标的5683端口，服务端返回DISCOVERY响应包。不满足CoAP定义的数据包格式，5683端口丢弃请求数据包不做响应。  
### 3.3 未授权访问  
  
函数未做鉴权处理导致未授权信息泄漏及相关操作。  
  
部分函数如下所示  
```
 handleCoapMethod("device/inform/boot", handler)
 handleCoapMethod("device/inform/system", handler)
 handleCoapMethod("device/inform/off", handler)
 handleCoapMethod("device/inform/on", handler )
 handleCoapMethod("device/inform/data", handler)
 handleCoadMethod("device/cmd/action", handler)
```  
  
攻击者可以直接访问以上接口进行相应操作。  
##  4. 安全风险   
- 代理跳板:黑客可以利用SOAP服务接管路由器的设备权限。  
  
- 内网渗透:边界设备开启UPNP没有做好鉴权处理，会导致攻击者通过该服务队内部网络进行内部渗透。  
  
- DDOS:黑客组织采用批量设备进行拒绝服务攻击，导致企业及机构相关业务停滞。  
  
##  5. 攻击思路   
- 是否可以通过资源发现操作获取服务端相关资源  
  
- 是否采用安全机制  
  
- 是否对接口设置鉴权  
  
- 相关接口实现是否存在相关漏洞  
  
##  总结   
  
CoAP是一种轻量级的通信协议，但在实际应用中仍需注意安全风险并采取相应的安全措施来保护通信的安全性和可靠性。  
  
  
