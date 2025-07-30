> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNzg4NTU0NQ==&mid=2247485804&idx=1&sn=aac724da59eb2431e4883e1384ba7310

#  重生之hw 0day出自我的cnvd  
原创 Syst1m  Zer0 sec   2025-07-02 07:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/lSfs7HwzmOPCo1kGc4zXkibXgtwOyYI11LQiarcibLiazDfxj8nSwNy7WHma4BfeqQdzvGZ6EicCj3Y9Lrzu1V4Kv0w/640?wx_fmt=gif&from=appmsg "")  
  
**攻防演练第一天的 “熟悉面孔”**  
  
  
本推文提供的信息、技术和方法仅用于教育目的。文中讨论的所有案例和技术均旨在帮助读者更好地理解相关安全问题，并采取适当的防护措施来保护自身系统免受攻击。  
  
严禁将本文中的任何信息用于非法目的或对任何未经许可的系统进行测试。未经授权尝试访问计算机系统或数据是违法行为，可能会导致法律后果。  
  
作者不对因阅读本文后采取的任何行动所造成的任何形式的损害负责，包括但不限于直接、间接、特殊、附带或后果性的损害。用户应自行承担使用这些信息的风险。我们鼓励所有读者遵守法律法规，负责任地使用技术知识，共同维护网络空间的安全与和谐。  
  
  
事情是这样的，摸鱼的时候看看第一天hvv的资讯，看见下面这条消息  
  
![baf2b0c76b8f870bc73d1b7251e8c8c.jpg](https://mmbiz.qpic.cn/mmbiz_jpg/lSfs7HwzmOPCo1kGc4zXkibXgtwOyYI11mlctUA32XiaTO0ujt601txib5D8KibDciaqiaPKialCYJLt7icjFC8PYX25aw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
看着我觉得怎么这么眼熟，突然反应过来（打工人精神涣散，反应迟钝是这样了），这不是我去年挖CNVD的洞吗哈哈哈  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmOPCo1kGc4zXkibXgtwOyYI11ibFTk1HBA5ejM6QAicv5gftCKJSlia7yq6saEBbMmxTp56l3v4MdbkTbA/640?wx_fmt=png&from=appmsg "")  
  
![5585d48e785e2fbc748883acfb592e2.jpg](https://mmbiz.qpic.cn/mmbiz_jpg/lSfs7HwzmOPCo1kGc4zXkibXgtwOyYI11xsicfc8JfEeia3Wh0nRiawxUfJtgKbBeXcXt9TMLkkRh02pyfaXA72kBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
外部交流群（欢迎进群互相交流）：由于群人数超过了200，只能邀请拉群，可以关注公众号，后台回复“加群”，获取助手绿泡泡，联系小助手邀请进群  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/lSfs7HwzmOPQ0wFex2MNKbDRZ2sAzNCAMvALMuUhBbiazlVRN2P3ib3wPCuoMWibCUJvJNdAhBXKC6KHNBUWTr1vg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
