#  Jasmin勒索软件Web面板路径遍历PoC   
 Ots安全   2024-04-10 18:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
Jasmin勒索软件Web面板路径遍历PoC  
  
#EducationalPurposes  
  
https://github.com/codesiddhant/Jasmin-Ransomware  
  
我在 Jasmin Ransomware Web 面板 (CVE-2024-30851) 中发现了一个预身份验证路径遍历漏洞，允许攻击者对面板操作员进行去匿名化并转储解密密钥。在最近的 TeamCity（CVE-2024-27198、CVE-2024-27199）利用活动中观察到 Jasmin 勒索软件 ( https://twitter.com/brody_n77/status/1765145148227555826 )  
  
  
**重定向后执行 (CWE-698)**  
  
受影响的端点 (Jasmin-Ransomware/Web Panel/download_file.php) 在发送 Location 标头后无法 die()。这允许攻击者绕过身份验证要求。对 readfile 的调用未经过滤，允许攻击者读取任意文件。  
```
<?php
session_start();
if(!isset($_SESSION['username']) ){
  header("Location: login.php");
}
$file=$_GET['file'];
if(!empty($file)){
    // Define headers
    header("Cache-Control: public");
    header("Content-Description: File Transfer");
    header("Content-Disposition: attachment; filename=$file");
    header("Content-Type: text/encoded");
    header("Content-Transfer-Encoding: binary");

    // Read the file
   readfile($file);
```  
  
  
所以POC使用请用虚拟环境食用 -项目地址：  
  
https://github.com/chebuya/CVE-2024-30851-jasmin-ransomware-path-traversal-poc  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
