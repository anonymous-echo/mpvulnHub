#  [CTF复现计划]2024巅峰极客初赛 easy_java   
原创 DatouYoo  大头SEC   2024-08-21 18:02  
  
## 题目信息  
> 本题涉及知识点：JDK17不出网打CB（实则CC）  
  
- • 题目类型：CTF  
  
- • 题目名称：2024巅峰极客初赛 easy_java  
  
- • 内部端口：8088  
  
## 启动脚本  
```
docker run -itd -p 18088:8088 -e FLAG=flag{8382843b-d3e8-72fc-6625-ba5269953b23} ccr.ccs.tencentyun.com/lxxxin/public2:dfjk2024_easy_java
```  
## WriteUp  
  
黑盒题，没太多可以说的，Commons-Beanutils 1.9+自带Commons-Collections3.2.1，题目过滤了org.apache字样，用UTF8-Overlong-Encoding绕过即可，题目不出网，用defineClass加载字节码打内存马即可。  
  
参考：https://t.zsxq.com/3dFFM  
  
运行EXP类时记得添加VM选项：  
```
--add-exports=java.base/sun.nio.ch=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-exports=jdk.unsupported/sun.misc=ALL-UNNAMED
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsicib7j3akF8D3MGnjfibVFVfUp5n14o28ZSfPEZ9lLtwxrLDSECw8Q0Ylr26wJiakyuSfocROIR28Ymw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
由于EXP篇幅太大，直接粘贴至公众号会有格式问题，完整EXP参考下方gist链接：  
- • https://gist.github.com/LxxxSec/6e5d3e12a283915790f8f93f66a57487  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsicib7j3akF8D3MGnjfibVFVfUI42qEFniaUcOLZjceZxBDz4x12HibNLOqXicqIEjI4STIIYgEqC14bbcQ/640?wx_fmt=png&from=appmsg "")  
  
利用效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsicib7j3akF8D3MGnjfibVFVfUq2XWeBL4DauY9ib1YDDoVfVhoKzJib01GfIurdWJ0UBtRibhU1UBaSypg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
  
