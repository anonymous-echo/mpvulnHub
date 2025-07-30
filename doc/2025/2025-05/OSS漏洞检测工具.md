#  OSS漏洞检测工具   
原创 信安路漫漫  信安路漫漫   2025-05-07 23:01  
  
前言以前总结过OSS可能存在的安全问题，本次找到了一个可以自动化检测的工具分享一下。Cloud-Bucket-Leak-Detection-Toolsgithub地址https://github.com/UzJu/Cloud-Bucket-Leak-Detection-Tools使用方式以阿里云OSS为例单个检测python3 main.py -aliyun [存储桶URL]批量检测# 使用-faliyun python3 main.py -faliyun url.txt如下图扫描出来的结果其它几个云厂商的使用跟阿里云一致OSSFileBrowse 这边还有一款OSS扫描工具，带有图形化界面github地址https://github.com/YH-JY/OSSFileBrowse使用java -Dfile.encoding=UTF-8 -jar OSSFileBrowse-1.0-SNAPSHOT.jar总结本次介绍了两个OSS漏洞的检测工具，可以覆盖了大部分的OSS方面的漏洞，大家测试的过程中可以使用一下。  
  
