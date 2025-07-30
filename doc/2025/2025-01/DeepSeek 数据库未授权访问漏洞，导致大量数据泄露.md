#  DeepSeek 数据库未授权访问漏洞，导致大量数据泄露   
安全透视镜  网络安全透视镜   2025-01-31 02:37  
  
Wiz Research 团队，近日国外爆出DeepSeek 的一套可公开访问的 ClickHouse 数据库，允许对数据库进行完全控制，包括访问内部数据。此次暴露包含超过一百万行的日志流，其中含有聊天记录、密钥、后端细节以及其他高度敏感的信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7pHFURc2xA7dCXko0dibGFlU4XueyK3ZJicX6ru3CUEpUicAgQDjgx4UeehNvjousWq5rb5MdS6KGFA/640?wx_fmt=png&from=appmsg "")  
  
未授权详情  
  
•  
http://oauth2callback.deepseek.com:8123[3]  
•  
http://dev.deepseek.com:8123[4]  
•  
http://oauth2callback.deepseek.com:9000[5]  
•  
http://dev.deepseek.com:9000[6]  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS7pHFURc2xA7dCXko0dibGFlxbX1xV7uDgdEGZy9GFC4ztZobFzhXwUsbwquUm6FFp4eplQ0nJUIow/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS7pHFURc2xA7dCXko0dibGFlWZgOjSJiaHtGxj1jtJicAMfxPSlC3WyvcNNKXZ3c5ppYDCeMib0icLST4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS7pHFURc2xA7dCXko0dibGFlb6SPCYB4Cyy8qeXZXichnd7GKPLSlMeyaTrs73a4BGGs8L8kqLcSc5g/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS7pHFURc2xA7dCXko0dibGFlfUAt3xMhS2ibWbxlYEA4Uh3RgcueOZGDib8ZlYLJLxdVfabruzwvvMDw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS7pHFURc2xA7dCXko0dibGFlat8Aic9vIrkcia41MKPc2PnFEtk6jJibzmJ66fb5Mp2R5uXcAhc0NMGUg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS7pHFURc2xA7dCXko0dibGFlDw09q1a4NNqyunjia0VlO9rkmxSyfe1dlCzeIwvh9EKW2M5qNibRh2Kw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
