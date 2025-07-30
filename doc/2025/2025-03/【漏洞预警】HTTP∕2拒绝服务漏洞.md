#  【漏洞预警】HTTP/2拒绝服务漏洞   
cexlife  飓风网络安全   2025-03-03 22:32  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00twOXVCel6uOS1NLgohCOzTO77iaZP8ltoImz44zeL8GjPKiciaKdmdmU8aQGVpe7LZvNkZZ56bU1iaw/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
攻击者可能会通过发送过量的CONTINUATＩON帧来导致HTTP/2端点读取任意数量的标头数据.维护HPACK状态需要解析和处理连接上的所有HEADERS和CONTINUATION帧.当请求的标头超过 MахHеаdеrBуtеѕ时,不会分配内存来存储多余的标头,但仍会解析它们。这允许攻击者导致HTTP/2端点读取任意数量的标头数据,所有这些数据都与将被拒绝的请求相关联,这些标头可以包含霍夫曼编码的数据,接收者解码该数据的成本比攻击者发送的成本高得多,该修复对我们在关闭连接之前处理的多余标头帧的数量设置了限制。  
  
影响产品:  
  
1、 1.22.0-0 <= golang < 1.22.2  
  
2、 golang < 1.21.9  
  
3、 golang.org/x/net/http2 < 0.23.0   
  
修复建议:  
  
目前官方已有可更新版本,建议受影响用户升级至最新版本:  
  
ɡоlаｎɡ >= 1.22.2  
  
ɡоlаｎɡ >= 1.21.9  
  
ɡоlаnɡ.оrɡ/х/nеt/ http2 >= 0.23.0  
  
官方补丁下载地址:  
  
https://pkg.go.dev/vuln/GO-2024-2687   
  
  
  
