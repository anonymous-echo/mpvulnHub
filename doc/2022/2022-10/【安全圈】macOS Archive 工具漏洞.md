#  【安全圈】macOS Archive 工具漏洞   
 安全圈   2022-10-11 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EsJgoSfP3LdytT5YJtFF2lxa1eoz3iaG3MyicgklF57GGGRYzBUrmWqKA/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
macOS  
  
  
据ROARTALK网站消息，macOS Archive工具漏洞可绕过Gatekeeper检查，未签名的应用也可以在不向用户展示安全提醒的情况下执行。  
  
  
Archive Utility是macOS系统自带的归档实用工具。Jamf Threat Labs安全研究人员在macOS Archive工具中发现了一个安全漏洞，漏洞CVE编号CVE-2022-32910。攻击者利用该漏洞可以构造压缩文件可以在不向用户展示安全提醒的情况下执行未签名的应用。  
  
  
Archive工具可以提取不同压缩文件格式，包括7-ZIP、ZIP、TAR、CPIO、GZIP 和Apple Archive。一般情况下，双击支持的文件格式默认会使用Archive工具来处理压缩文件的解压缩。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9E1vluzpjowFSMONkkgNIj2HKF3nV6QBqTgud9SZfx9TrrCiahSdH3uAw/640?wx_fmt=jpeg "")  
  
漏洞分析  
  
  
研究人员使用aa命令创建包含图片的压缩文件，目录结构如下所示：  
  
  
aa archive -d images -o myPictures.aar  
  
该压缩文件中含有images目录中的所有文件和文件夹，并输出名为myPictures.aar的压缩文件。如果压缩文件是下载的，且没有解压，目录结构如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EfJp1sm45cTGQ3qvwDVibFME9QYxLeVMBaAHc0ZPwtgeicibB6CQJZiascw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9Et9oAAvlqriaiaxBRJsh1y8A8ibXFAK6rb61otsezCJ8oZS03vqYwYM3GA/640?wx_fmt=jpeg "")  
  
然后，研究人员使用相同命令在该文件夹中添加一个文件4.png：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EPy2eticuEyN0fniaiamZfFCQY1yFHQSG1vn0fwo5lsHVeatmTcrwHLBjQ/640?wx_fmt=jpeg "")  
  
然后，再次下载压缩文件，并打开：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9E8t1CUOfBn3ic28kia6TicbElFfFl4qxulg6CCyr3BLj358S1KclLmatJw/640?wx_fmt=jpeg "")  
  
使用Archive工具解压后，可以看到明显的区别：myPictures.aar文件解压后，Archive工具会创建一个名为myPictures的文件夹，其中含有文件4.png，myPictures文件夹中不含有com.apple.quarantine 扩展属性，但是其中的文件4.png包含该属性。  
  
  
在解压过程中，包括Archive Utility、AUHelperService和ArchiveService在内的多个进程都包含在内。研究人员使用苹果的终端安全工具监控了文件使用，发现ArchiveService进程将提取的内容写入到了以下临时目录：  
  
  
/private/var/folders/{2-random-characters}/{31-random-characters}/T/com.apple.fileprovider.ArchiveService/TemporaryItems/NSIRD_ArchiveService_{6-random-characters}  
  
  
Archive工具中包含一个名为_propagateQuarantineInformation的函数。ArchiveService进程确保quarantine属性在文件转移到目标位置前传播到了所有提取的内容中。并调用了libquarantine.dylib中的底层函数_qtn_file_apply_to_path，将quarantine属性应用到位于NSIRD_ArchiveService_XXXXXX 临时目录的解压文件中。  
  
{  "event": "ES_EVENT_TYPE_NOTIFY_RENAME",  "file": {    "proc_path": "/System/Library/CoreServices/Applications/Archive Utility.app/Contents/XPCServices/AUHelperService.xpc/Contents/MacOS/AUHelperService",    "destination": "/Users/jpcore/Downloads/myPictures",    "original": "/private/var/folders/pp/slmzl7sd41z3h1rc4wqdndxr0000gn/T/com.apple.fileprovider.ArchiveService/TemporaryItems/NSIRD_ArchiveService_0uhVx9",    "pid": 3718  },  "timestamp": "2022-09-16 14:43:19"}  
  
但ArchiveService并未将quarantine属性应用到NSIRD_ArchiveService_XXXXXX文件夹，只应用到了提取的文件中。  
  
  
AUHelperService调用_decompressMoveCopyResults 函数来将提取的内容从临时目录转移到目标位置，具体过程如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9E03j9C6YibzUIKjYRSwibxaFBdQMw9WgfcqFZbNibdKFYL8YfYXewucM1w/640?wx_fmt=jpeg "")  
  
· 函数提取路径到临时文件夹中的提取压缩文件中；  
  
· 函数提取路径到下周的压缩文件中；  
  
· 从路径中提取压缩文件的文件名；  
  
· 移除压缩文件的文件扩展名。  
  
· 最终，myPictures文件夹中没有quarantine属性。  
  
  
**漏洞利用**  
  
****  
漏洞利用条件：  
  
· 压缩文件的文件名必须包含.app扩展，比如test.app.aar；  
  
· 在目标目录的根目录下（test.app/)）有2个以上的文件或文件夹，这会引起临时目录自动重命名；  
  
· 只有app中的文件和文件夹被压缩， test.app目录除外；  
  
  
漏洞利用：  
  
使用aa工具可以构造压缩文件：  
  
aa archive -d test.app -o test.app.aar  
  
用户下载和打开该压缩文件，使用Archive工具打开：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EhKFMQqG84m3E5hUxBJJkxHNOg3jesyFC3ibmqq6N0VqzPsVj46pZic8w/640?wx_fmt=jpeg "")  
  
可以看到其中没有quarantine属性，因此可以绕过Gatekeeper检查，因此所有未签名的二进制文件可以执行。  
  
  
研究人员使用Apple Archives格式进行了测试，但使用zip文件格式也可以完成绕过。  
  
  
**漏洞修复**  
  
****  
研究人员于2022年5月31日将该漏洞提交给了苹果公司。苹果公司已于2022年7月20日修复了该漏洞。  
  
  
苹果公司通过额外调用_qtn_file_apply_to_path来更新_propagateQuarantineInformation 函数的方式修复了该漏洞。修复后，临时文件夹NSIRD_ArchiveService_XXXXXX在重命名之前已经应用了quarantine属性。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9ETjYicKErIedLrZONj8bNA4Htcn3E4dPWubgpjQJK9JbUMWhRNsNSaVg/640?wx_fmt=jpeg "")  
# 【安全圈】黑客直接入侵伊朗电视台新闻直播画面，抗议伊朗高层！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EqIcNq5KfbFxK7gIgFFJqRboU58u4WoJlTxoy0so93SXb3Nicfhjya1w/640?wx_fmt=jpeg "")  
# 【安全圈】印尼13亿张SIM卡数据泄露，印尼网友称其为“开源国家”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EKVnCRAkn2bWahEJvOLc6V1iagY0VhD8hzcqBvQ6wbXO29eKicH1fyNzw/640?wx_fmt=jpeg "")  
# 【安全圈】数量将近Edge 3倍！Chrome成2022年漏洞最多的浏览器  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaiaVROxlIH8pFLfycZibUc9EVt3Jmic4oXxHV54UPJYktNZXzxGkggTEB8HGneYQ7vVrmqmY5ZpdmZQ/640?wx_fmt=jpeg "")  
# 【安全圈】芯片制造商威刚否认遭到 RansomHouse 组织攻击  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
