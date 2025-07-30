#  Dify 组合漏洞获取LLM KEY   
 蓝云Sec   2025-05-07 12:28  
  
 项目地址:https://github.com/langgenius/dify  
  
1、前言：  
  
目前该漏洞大部分已经修复了，该文只用于学习，请勿用于非法。  
  
以下测试均为本地环境试验。  
  
最近正巧使用Nas+dify完成部分工作，dify搭建好发现了@e0mlja师傅刚发的文章  
  
2、漏洞利用  
  
dify的配置文件中其实有许多的默认密码不限于SQL、OpenSearch等，具体的可以自己去看一下，前面的攻击思路就是通过默认口令  
  
difyai123456连接postgresql，修改用户名密码(当然也可以去创建一个用户，可以参考e0mlja师傅的文章)  
  
进入到后台后，创建一个知识库，上传任意文件，到数据库中修改地址获取到private.pem(后面再说为啥要获取这个东西)  
  
最后找到加密后的key，写个解密脚本即可获取到key内容  
  
3、漏洞分析  
  
前面的内容一直到读取的部分，这里都不细说了，接下来只介绍key分析的部分  
  
3.1、分析加密方式  
  
先放图  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81YZwonVHQq97yYeJEaDt7m11C77DicaojTH1t7KFdkZicNALQEic5ODCYw/640?wx_fmt=png "")  
  
如果我们直接在后台查看API key会发现是被加密的，从页面提示可以看到是通过PKCS1_OAEP进行加密  
  
PKCS1_OAEP  
  
PKCS1_OAEP是RSA加密算法的一种填充方案，用于提高加密安全性。它通过哈希函数和随机数填充明文，使相同明文加密产生不同密文。其主要特点是安全性高，能有效抵御多种攻击，并能验证数据完整性。它常用于密钥传输、数字签名和安全存储等场景，是RSA加密中更安全的选择。  
  
这里我们知道大概逻辑后，下一步就是找三个东西了，私钥、公钥和密文  
  
找公钥只是为了验证我们私钥是否正确  
  
‍  
  
3.2、公钥、密钥获取  
  
公钥和密文这两个其实都比较好找  
  
公钥  
  
在数据库里面有个tenants的表，里面存放的我们工作空间的内容，当然也包含我们相关的公钥  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81AnfnyCu6pcVx2l6BosuRVMOKSpicSBdbw6KAOrWO5sN6FgBFVE1pksw/640?wx_fmt=png "")  
  
除了公钥以外，这个id也很重要，可以先记住，后面再详细说明是干啥用的  
  
密文  
  
密文存放位置在数据库中的providers表中  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81iaLZzGlfMEibSSMDQ2Qa5Xmqiagz0ZHHjnSaPAsWyYGsUDForjqSGicItQ/640?wx_fmt=png "")  
  
其中的encryptd_config也就是我们的key  
  
大概内容如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81ZQUKf8oercpgvklzp2n415292PPsSicGNrYaO9QnAIUiboyzYhicfNH2A/640?wx_fmt=png "")  
  
到这里我们前期需要的两个东西就有了，接下来是找私钥  
  
3.3、私钥获取  
  
全过程中最麻烦的一步  
  
3.3.1 获取私钥位置  
  
首先我们要分析私钥存放在哪个位置，才能去获取  
  
如果你仔细查看过官方文档会找到一个STORAGE_LOCAL_PATH的参数，而该参数的默认指向/app/api/storage在storage中则存放着我们的private.pem，具体可以参考官方文档内容  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81icTOY6WBI1POhYSIhlCibnIDTYibURnCzIG0kgiaJRSHGcd2sgQfiayARtQ/640?wx_fmt=png "")  
  
这里的内容需要好好看，不然接下来你会踩和我一样的坑  
  
这里知道private.pem的地址后我们可以去尝试拼接一下  
  
/app/api/storage/[工作空间id]/private.pem  
  
坑点1  
  
如果你也是用这样的方式去尝试进行读取，那么恭喜你成功踩了第一个坑  
  
你大概会得到如下结果  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81edfibEVDk7Yv2PUrotjOGnc7HTyaRtbCNc5oV2gbqibSu3yqtRdiaWiaXQ/640?wx_fmt=png "")  
  
因为  
/app/api/storage/[工作空间id]/private.pem并不是一个有效的绝对路径，你并不知道它前面还有哪些内容，当然如果你能推出它前面路径当我没说  
  
例如  
/var/docker/dify/test/app/api/storage/[工作空间id]/private.pem  
  
‍  
  
解决方法  
  
其实在最初的官方介绍中，我们便可以找到这个位置  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81YQt8t2obPWuGwricSWqVYW6jmdsfE6BibKNyXaEE2IJF9nPtianbrM6ZA/640?wx_fmt=png "")  
  
注意分析这句话，我们可以推断出upload_file和我们私钥应该处于同一目录下  
  
在github的源码中我找到了以下内容  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81LbiatFPedTMxQkOa3RKxstxcEbwJZpKzXzN1ZjNia5FxXd3ibTPuouAIg/640?wx_fmt=png "")  
  
ok，到这里其实已经很明显了，我们要找的私钥文件应当处于的相对位置是  
  
/storage/privkeys/[工作空间id]/private.pem  
  
这里我们起一个本地环境可以验证一下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H816M5Yo6hK664kd37vEEHkHicZg8H4qBllZqFxBkXke16mqkSKS6PZDdg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81ibiad4yAftLL9GR3gM0ONRW22jhCrkeT0BrzU1uILdYUWSx9Maskib5IA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81Iib4ZSicf43HBFKH0MHz4ECshQLbR9bXc8Q7JSicV0p2VicXMHAbjHFXUw/640?wx_fmt=png "")  
  
此处工作空间id和我们数据库中正好能够对应，由此推断为正确的private.pem  
  
那么就可以去获取一下我们的private.pem内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81oibeheZfANyJO9Te6hfPq18K55TZB3BAjKgB2WKvRdib1vzqzcunbQ3w/640?wx_fmt=png "")  
  
将获取到的密钥内容，按照.pem格式拼接即可  
  
当然，你也可以利用我们获取到的公钥对任意数据进行加密，尝试用获取到的私钥进行解密验证  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81T5dEQdFibTicoJzSqTlgRiaWPGM5WtY1jZDRB0zPF8pEQRg1lpsjsYujg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81krHyxzWfyVWRiaA52rQjHmJIqdC6RZ6QkQfpsemd1EeV4FAzvJdYdzw/640?wx_fmt=png "")  
  
结果显而易见  
  
‍  
  
到这里如果你觉得已经完了，那你会发现拿着这个私钥无法解密你获取到的密文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H819RbQY6iaQDXJvRqfI6BYRiczrWhKLevdYibsJqGS2kzicpc4bCAVU4aicaQ/640?wx_fmt=png "")  
  
这里也就是第二个坑  
  
为什么会无法解密呢？难道是因为私钥不对？如果是私钥不正确，那么我们刚才用公钥加密的内容便无法被成功解密。  
  
这里我的判断就是可能不存在一种加密方式  
  
3.4、解密脚本撰写及分析  
  
在api/commands.py中我们可以分析reset_encrypt_key_pair()命令会为每个工作空间（tenant）生成一对新的非对称密钥（RSA 2048位），私钥以 PEM 格式存储在   
privkeys/{tenant_id}/private.pem，公钥则保存在数据库字段 tenant.encrypt_public_key 中  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81N7Kuia9nw8G3NoKQupv0Tx2TkxL8eLoWpN9FpEg40PtDUBdZr5geNNA/640?wx_fmt=png "")  
  
在dify-main/api/libs/rsa.py通过encrypt函数实现AES加密  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81xwzgXXts3n1PdjtZFoH9xeTlmlep0upBbsPoAytBiac7f6EYOI96W8A/640?wx_fmt=png "")  
  
加密时，首先生成一个随机的 AES 密钥（16字节），用 AES（EAX模式）对明文进行加密，然后用租户的 RSA 公钥对 AES 密钥进行加密。  
  
最终密文格式为：HYBRID: 前缀 + 加密后的 AES 密钥 + AES nonce + tag + 密文内容。  
  
该加密数据会被 base64 编码后存储。  
  
解密流程  
  
解密时，先用工作空间的私钥解密出 AES 密钥，再用 AES 密钥解密数据内容，恢复明文。  
  
解密相关逻辑在 dify-main/api/libs/rsa.py 和 dify-main/api/core/helper/encrypter.py 中实现  
  
‍  
  
那么接下来，我们便可以通过上面的方法来实现  
  
总共两种实现方式  
  
1、可以直接调用 libs/rsa.py 里的 decrypt 方法。但是这种方式对我们来说并不是特别方便，需要本地安装环境  
  
2、写一个解密脚本  
  
大致内容如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81C6yFHRmopOcDTsD7d88eianxsEMwrqMQMeiaicv5dFgmEaFzwjrqYGM3w/640?wx_fmt=png "")  
  
最后成功获取KEY  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81Nia3mnmPw0xVltrBCftaXHfOlp6FSTkA2yYTlD5HooGbyTIl1ey8F0A/640?wx_fmt=png "")  
  
放到dify验证一下，确实可以使用  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81NkmrTHaTKgeCHGzS7G9xoTDebZQE9y5aetiaGK2Ur2KJZgvfiapbtDyQ/640?wx_fmt=png "")  
  
‍  
  
以上便是Dify key泄露全过程，如果上面还有看不明白的地方或者需要相应脚本和环境的，可以私信找我要完整版本，如有问题欢迎沟通。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Lviaxe5uzCI9Zr13b9AeLCwA43Qex0H81DxCxTAOVCfibCibmNqs8c0LOQVxF0KniaYqh4kSK5wClIwVUkrrk69ZvQ/640?wx_fmt=png "")  
  
  
