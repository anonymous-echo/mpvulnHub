#  Caddy能取代Nginx吗？   
原创 大表哥吆  kali笔记   2024-12-23 00:00  
  
> 最近Caddy这个项目挺火的，说是可以替代Nginx。本文让我们一起看看，它强大在什么地方。  
  
# 关于  
  
Caddy是一个用 Go 语言编写的开源 HTTP/2 web 服务器，它的主要优势是自动支持 HTTPS 和简洁的配置方式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatheYiaBsVShFcj6lMsHYx1DFCdCvhNCPw4LN2yPmxINjfm3ibQKM8RsG1iaHRah9maMWpWXbrpv5bxtQ/640?wx_fmt=png&from=appmsg "")  
  
**优势：**  
- 自动的HTTPS证书申请和自动续期。  
  
- 友好且强大的配置文件支持  
  
- 支持API动态调整配置  
  
- 支持HTTP3(QUIC)  
  
- 基于Go编写，高度模块化的系统方便扩展  
  
# 安装  
  
本文以Kali为例。执行apt命令即可安装。  
```
sudo apt install caddy

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatheYiaBsVShFcj6lMsHYx1DFX9KyyibpABdFSlRNAcLzsxN1P9a32rdShpvO83kZ1l4mcVyF09enbFw/640?wx_fmt=png&from=appmsg "")  
  
如果apt命令安装不了，  
需  
要更新源  
。  
```
udo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy

```  
# 牛刀小试  
  
默认情况下，Caddy的配置文件在/etc/caddy/Caddyfile  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatheYiaBsVShFcj6lMsHYx1DFuTEqMqjRviathCkmr65Zdmic4QSeu5u5vtIzLaI543PnKLazm5SCJ20w/640?wx_fmt=png&from=appmsg "")  
  
在初始状态下，默认为80端口。只需要配置root * /usr/share/caddy（站点的位置）
如:  
```
root * /var/www/html

```  
  
当然，Caddyfile文件可以放到任意位置，如你的站点目录下，放入后执行下面命令重新载入即可！  
```
sudo caddy reload

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatheYiaBsVShFcj6lMsHYx1DF7fSerXj6Hb8Mp5m9qvRtgr94GictCt8EIicApzpKUibcH8BQ6Acneb8qw/640?wx_fmt=png&from=appmsg "")  
  
**启动**  
  
caddy的启动，有两个命令，一个是caddy run，一个是caddy start，两者的区别就是后者是守护进程的方式启动。![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatheYiaBsVShFcj6lMsHYx1DFEWicpK4nf6icUxFqRnsjkWrUmDzdtrtuXafaBkbicOwnVGsv8bF64SLOA/640?wx_fmt=png&from=appmsg "")  
  
# 配置PHP  
  
在配置文件中新增命令  
```
php_fastcgi localhost:9000
#或者
php_fastcgi unix//run/php/php8.2-fpm.sock

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatheYiaBsVShFcj6lMsHYx1DFm7yNoibKYMwrL77aT65whHXJZ1CcD3EhVJRyttibqLoCaXxaqfR9JibVg/640?wx_fmt=png&from=appmsg "")  
# https站点  
  
现在我们来看看Caddy最牛叉的地方。看看他是如何与Nginx相媲美的。  
  
**自动化https**  
```
www.nb.com {
#站点目录
root * /var/www/html
#申请证书时所需的邮箱
tls test@qq.com
file_server
}


```  
  
简单吧~ 总而言之，Caddy最大的厉害之处，是自动向Let’s Encrypt申请证书、续签证书，自动配置全站https。当然，我们还要考虑自身的情况和实际生产环境，请勿盲目跟风！  
  
**更多精彩文章 欢迎关注我们**  
  
  
  
