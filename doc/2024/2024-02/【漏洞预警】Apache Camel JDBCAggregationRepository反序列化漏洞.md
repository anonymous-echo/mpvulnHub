#  【漏洞预警】Apache Camel JDBCAggregationRepository反序列化漏洞   
cexlife  飓风网络安全   2024-02-20 21:25  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02ft6yQowoRTty5HoXk6oiaVzSlyibKOMvO8VJ1VicywD1F9kP2EjzRLib7IYynOiaYSOkojWdlCBnEkWw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Apache Camel 是开源的系统间数据交互集成框架,在受影响版本中,由于对JDBCAggregationRepository中exchange的实现存在未限制的反序列化逻辑,当攻击者可控制数据库中exchange字段值时,可以反序列化任意类,造成任意代码执行,在修复版本中,通过校验逻辑限制其仅允许反序列化java及camel自身类。**影响范围:**org.apache.camel:camel-sql[3.0.0, 3.21.4)org.apache.camel:camel-sql[3.22.0, 3.22.1)org.apache.camel:camel-sql[4.0.0, 4.0.4)org.apache.camel:camel-sql[4.1.0, 4.4.0)**修复方案:**升级org.apache.camel:camel-sql到3.21.4、3.22.1、4.0.4、4.4.0或更高版本**参考链接:**https://issues.apache.org/jira/browse/CAMEL-20303https://lists.apache.org/thread/3dko781dy2gy5l3fs48p56fgp429yb0f  
  
