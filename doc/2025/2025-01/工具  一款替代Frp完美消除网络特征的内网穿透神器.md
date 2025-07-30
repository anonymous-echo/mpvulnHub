#  工具 | 一款替代Frp完美消除网络特征的内网穿透神器   
howmp  HACK之道   2025-01-23 02:00  
  
   
  
### 介绍  
  
grs是一个反向socks5代理,其中grss和grsc和grsu是通过REALITY协议通信。相对于frp，nps等内网穿透工具有以下特点:  
  
```
完美消除网络特征
防止服务端被主动探测
客户端和用户端内嵌配置，不需要命令行或额外配置文件
```  
  
  
   
  
### 使用教程  
  
  
   
  
grs共有3个程序，分别代表着以下含义:  
```
grss(Golang Reverse SOCKS5 Server) 服务端，需要有公网IP的机器上
grsc(Golang Reverse SOCKS5 Client) 客户端，需要运行于想要穿透的内网中机器上
grsu(Golang Reverse SOCKS5 User) 用户端，需要运行于用户机器上，提供socks5服务
```  
  
在初次使用的时候需要生成配置、客户端、用户端相关信息  
```
grss gen www.qq.com:443 127.0.0.1:443
```  
- www.qq.com:443 是被模拟的目标  
  
- 127.0.0.1:443 是服务器监听地址，这里要填写公网IP，端口最好和模拟目标一致  
  
若SNIAddr或ServerAddr不指定，则尝试加载已有配置文件。默认生成3个不同id文件名的客户端，可通过-c  
参数指定  
```
Usage:
  grss [OPTIONS] gen [gen-OPTIONS] [SNIAddr] [ServerAddr]

generate server config and client

Help Options:
  -h, --help                                                 Show this help message

[gen command options]
      -d                                                     debug
      -f=[chrome|firefox|safari|ios|android|edge|360|qq]     client finger print (default: chrome)
      -e=                                                    expire second (default: 30)
      -o=                                                    server config output path (default: config.json)
      -c=                                                    client count (default: 3)
      -s                                                     skip client cert verify
          --dir=                                             client output directory (default: .)

[gen command arguments]
  SNIAddr:                                                   tls server address, e.g. example.com:443
  ServerAddr:                                                server address, e.g. 8.8.8.8:443
```  
  
**启动服务端：grss serv**  
```
Usage:
  grss [OPTIONS] serv [serv-OPTIONS]

run server

Help Options:
  -h, --help      Show this help message

[serv command options]
      -o=         server config path (default: config.json)
```  
### 启动客户端：grsc X  
```
X表示id
```  
### 启动用户端：grsu -id 0     
  
这里id参数对应了grsc的id，不同id会连接不同的grsc  
```
Usage of grsu:
  -i uint
        id
  -l string
        socks5 listen address (default "127.0.0.1:61080")
```  
  
   
  
### 项目地址  
  
  
   
  
https://github.com/howmp/reality  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
