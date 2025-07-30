#  闭源系统半自动漏洞挖掘工具 SinkFinder   
 进击的HACK   2024-12-12 23:55  
  
- 闭源系统半自动漏洞挖掘工具，针对 jar/war/zip 进行静态代码分析，增加 LLM 大模型能力验证路径可达性，LLM 根据上下文代码环境给出该路径可信分数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢  
！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
## 介绍  
  
闭源系统半自动漏洞挖掘工具，针对 jar/war/zip 进行静态代码分析，增加 LLM 大模型能力验证路径可达性，LLM 根据上下文代码环境给出该路径可信分数  
> [https://mp.weixin.qq.com/s/pKA0eG0B_yMkeV2-C1edWw](https://mp.weixin.qq.com/s?__biz=Mzg5ODE3NTU1OQ==&mid=2247484406&idx=1&sn=4ebabbc7065f50f5a101437e02b5f55d&scene=21#wechat_redirect)  
  
  
  
项目地址：  
https://github.com/Phelaine/SinkFinder  
> LLM 大模型 采用的是阿里的通义大模型，默认为空，需要配置API key。  
  
  
下面是没配API key的案例。  
## 参数说明  
```
java -jar SinkFinder-1.0-SNAPSHOT-jar-with-dependencies.jar -h _ _ __ _ _ (_) | | / _|(_) | | ___ _ _ __ | | __| |_ _ _ __ __| | ___ _ __ / __|| || '_ \ | |/ /| _|| || '_ \ / _` | / _ \| '__| \__ \| || | | || < | | | || | | || (_| || __/| | |___/|_||_| |_||_|\_\|_| |_||_| |_| \__,_| \___||_| 0.2@medi0cr1ty usage: SinkFinder -cb,--class_exclusions <arg> 自定义class_exclusions规则，类黑名单 -ci,--class_inclusions <arg> 自定义class_inclusions规则，类白名单 -d,--depth <3> 指定递归查找深度 -h,--help 帮助 -jb,--jar_exclusions <arg> 自定义jar_exclusions规则，jar包黑名单 -ji,--jar_inclusions <arg> 自定义jar_inclusions规则，jar包白名单 -l,--llm 启用通义大模型能力 -lk,--llm_key <arg> 配置通义大模型 API KEY（sk-xxx） -p,--path <arg> 指定目标分析路径 -r,--rule <rules.json> 指定Sink JSON规则路径，初始化默认resources/rules.json -s,--sink <arg> 自定义sink规则 -scb,--sink_category_block <arg> 禁用sink规则类别 -sci,--sink_category_include <arg> 配置sink规则类别
```  
  
配置通义大模型 需要api key  
## 运行命令  
```
java-jarSinkFinder.jar-p 代码路径 -d 遍历路径递归深度
```  
  
**测试**  
  
靶场：  
https://github.com/tangxiaofeng7/SecExample  
  
java -jar SinkFinder.jar -p secexample-1.0.jar -d 3  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3FiaNRLa1hsMwapxwQicFyI6zb8ackbZ27lYaVlgicpEG296Xw4riauicFVlg/640?wx_fmt=png&from=appmsg "")  
  
logs 目录中查看结果  
- llm 结尾文件： 已过滤 source + LLM 结果  
  
- true 结尾文件：已过滤 source  
  
- false 结尾文件：未过滤 source ，所有结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3F7qtvn3UuMKj8xrxLaRU33N5LsdAXeKcCJGV2qtKD8sQxFSqQMfpfGQ/640?wx_fmt=png&from=appmsg "")  
  
日志中显示检测出的漏洞，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3F6M45Hp9RjhKTqSu0F5zKqkRjicEMzhW92ZmK91pMW5Nftf5w56cK8cA/640?wx_fmt=png&from=appmsg "")  
  
以fastjson举例，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3FiahBxa4vUzpMhniah7Kh7Osl1u9ibYeEcxdkQiahJ7FKib2NlpwPP4B463A/640?wx_fmt=png&from=appmsg "")  
  
recaf 反编译 jar包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3FpheSozQIr5yVMwbAYWwOojJiappR86lmKMrmBD5EBFjUwBMVIbXlE7w/640?wx_fmt=png&from=appmsg "")  
  
可以看到此处确实存在fastjson反序列化漏洞  
  
Runtime RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3FNwRNJqwSjeY1KMkCMZR0DLZUGEjWRg6p5DFCTKGaf7eJicUr5kRvZKg/640?wx_fmt=png&from=appmsg "")  
## 总结  
- 规则少  
  
- 漏报多  
  
- 但准确率还可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaDAuDsPj1rzVV01T5z0q3F7Giat04zia5uteUIRISuqOby0h91vDOaPQiaRmiag0gEmuPZfjbWFjpSgA/640?wx_fmt=png&from=appmsg "")  
  
  
往期推荐  
  
[2024下半年软考成绩可查，压线过](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247487009&idx=1&sn=fec4735b3a70814a088b718a0695f514&scene=21#wechat_redirect)  
  
  
[Burpsuite存储桶配置不当漏洞检测插件](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486968&idx=1&sn=7ee147a6efd7c1a074d8acd00e67fe4a&scene=21#wechat_redirect)  
  
  
[burpsuite SQL注入插件](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486953&idx=1&sn=ab10862e21c3541f3bf996f5396697ec&scene=21#wechat_redirect)  
  
  
[轻松编辑修改jar包工具 Recaf](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486945&idx=1&sn=d9459f4760dc0caded551f03b28d1df3&scene=21#wechat_redirect)  
  
  
[apk 变得可调试 debuggable=true](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486880&idx=1&sn=36467fed439ed3885914463567bffb32&scene=21#wechat_redirect)  
  
  
[IDA 动态调试之反反调试](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486870&idx=1&sn=b44669b43a54f84f0e3e4eaa2c7dd25d&scene=21#wechat_redirect)  
  
  
[JWT sign 未校验导致未授权用户登录](https://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486862&idx=1&sn=2e0bbc1f67930c8ae0dd31032e4bad4f&scene=21#wechat_redirect)  
  
  
[基于flutter的Android vpn代理工具](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486777&idx=1&sn=9c0144199ee718665d6bd790bfb1ee26&chksm=c150aad2f62723c4c2ecbcb94e2d7edbcf4064074d512b96620401dfe59e692ed136406b9dfe&scene=21#wechat_redirect)  
  
  
[Jar Obfuscator - 图形化 JAR/CLASS 字节码混淆工具](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486687&idx=1&sn=bd93740fbab2f192142c3c56ee3c3074&chksm=c150ab34f62722221c32a6cd3b9e051fe0f7383d8c7fae763d428b8a117d61eacd43bbe01428&scene=21#wechat_redirect)  
  
  
[降低js逆向分析难度的油猴脚本](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486673&idx=1&sn=d7ca2ae0861850d4807ff558468c79ba&chksm=c150ab3af627222c68566213b34cbcdbe0ca008bf01303c539364ae906259f1490d3cab3d265&scene=21#wechat_redirect)  
  
  
[简单绕过 IOS应用 frida检测](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486561&idx=1&sn=6582b889e69674b5bfc7c817ec7ce2b3&chksm=c150ab8af627229c4fa75be0bc1f27e24aef5a51059fb88b7e6de9e0bf33f93aeaa3479a0294&scene=21#wechat_redirect)  
  
  
  
