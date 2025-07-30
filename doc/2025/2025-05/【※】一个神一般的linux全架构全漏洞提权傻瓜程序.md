#  【※】一个神一般的linux全架构全漏洞提权傻瓜程序   
原创 zngeek  蓝极战队   2025-05-05 12:09  
  
涵盖了所有linux架构目前已知漏洞的提权。  
  
编译了386、arm64和amd64。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib5EIMWjNGUsDOD4IniaOQfBeGpgEiaaoFhAibpl41QGQW8oFMo5y56KGWXDe7CUHrmSCH4RCo7VwgYcVqCgcxosJg/640?wx_fmt=png&from=appmsg "")  
  
因为是公开版，追求的就是一个傻瓜式操作，方便快捷，所有我只保留了一键测试利用以及输入当前用户密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib5EIMWjNGUsDOD4IniaOQfBeGpgEiaaoFhgOLo5M5UohcyK2aZWOaHQBqOWTWlpVTWpIf1GnByKGBBdQhOJAOXUA/640?wx_fmt=png&from=appmsg "")  
  
开发版本我预留了更多的功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib5EIMWjNGUsDOD4IniaOQfBeGpgEiaaoFhCYXzs7ia6mDBjLq4Smsy7Q6bWpTg4YqicO3kJSTkK7jOw2an6icraZXQw/640?wx_fmt=png&from=appmsg "")  
  
  
  
其实发布版本完全够用，直接运行程序会检测当前系统存在的所有漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib5EIMWjNGUsDOD4IniaOQfBeGpgEiaaoFhqN1aX4nibUDxvtZpMtZE7sXs46ezPT5HQeRae9WfdXsrLjiaaQpQtUMg/640?wx_fmt=png&from=appmsg "")  
  
支持的漏洞列表如下（这里要非常感谢某大神对于漏洞的支持）：  
```
docker:writable-socket
polkit:CVE-2021-3560
polkit:CVE-2021-4034
kernel:CVE-2022-0847
gtfobins:apt-get
gtfobins:apt
gtfobins:ash
gtfobins:awk
gtfobins:bash
gtfobins:bundler
gtfobins:busctl
gtfobins:busybox
gtfobins:byebug
gtfobins:capsh
gtfobins:check_by_ssh
gtfobins:check_cups
gtfobins:cowsay
gtfobins:cowthink
gtfobins:cpan
gtfobins:cpulimit
gtfobins:crash
gtfobins:csh
gtfobins:dash
gtfobins:dmesg
gtfobins:dpkg
gtfobins:eb
gtfobins:ed
gtfobins:emacs
gtfobins:env
gtfobins:ex
gtfobins:expect
gtfobins:find
gtfobins:flock
gtfobins:ftp
gtfobins:gawk
gtfobins:gcc
gtfobins:gdb
gtfobins:gem
gtfobins:ghc
gtfobins:ghci
gtfobins:gimp
gtfobins:git
gtfobins:gtester
gtfobins:hping3
gtfobins:iftop
gtfobins:ionice
gtfobins:irb
gtfobins:journalctl
gtfobins:jrunscript
gtfobins:ksh
gtfobins:less
gtfobins:logsave
gtfobins:ltrace
gtfobins:lua
gtfobins:mail
gtfobins:make
gtfobins:man
gtfobins:mawk
gtfobins:more
gtfobins:mysql
gtfobins:nano
gtfobins:nawk
gtfobins:nice
gtfobins:nmap
gtfobins:node
gtfobins:nohup
gtfobins:nsenter
gtfobins:pdb
gtfobins:perl
gtfobins:pg
gtfobins:php
gtfobins:pic
gtfobins:pico
gtfobins:pry
gtfobins:psql
gtfobins:puppet
gtfobins:python
gtfobins:rake
gtfobins:rlwrap
gtfobins:rpm
gtfobins:rpmquery
gtfobins:rsync
gtfobins:ruby
gtfobins:run-mailcap
gtfobins:run-parts
gtfobins:rview
gtfobins:rvim
gtfobins:scp
gtfobins:screen
gtfobins:script
gtfobins:sed
gtfobins:service
gtfobins:setarch
gtfobins:sftp
gtfobins:slsh
gtfobins:socat
gtfobins:split
gtfobins:sqlite3
gtfobins:ssh
gtfobins:start-stop-daemon
gtfobins:stdbuf
gtfobins:strace
gtfobins:tar
gtfobins:taskset
gtfobins:tclsh
gtfobins:time
gtfobins:timeout
gtfobins:tmux
gtfobins:unshare
gtfobins:valgrind
gtfobins:vi
gtfobins:vim
gtfobins:vimdiff
gtfobins:watch
gtfobins:wish
gtfobins:xargs
gtfobins:zip
gtfobins:zsh
```  
  
直接  
```
./znlinux -a
```  
  
傻瓜式一键利用返回root的shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib5EIMWjNGUsDOD4IniaOQfBeGpgEiaaoFhJvDlmsaVYJp5S7mpCVkyib91HbfMxbZqjpm7uRqyYoCVB02DLVfPrlg/640?wx_fmt=png&from=appmsg "")  
  
当然加一个-p输入当前用户的密码（已知情况下）在没办法提权的情况下有一定帮助，但是基本用不上！！！！  
```
./znlinux -a -p
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib5EIMWjNGUsDOD4IniaOQfBeGpgEiaaoFhbibJqOfHTzduykAfnPmk9uDibBjyVDQRJF93C4JKqb677sXZsq0oKHZg/640?wx_fmt=png&from=appmsg "")  
  
  
关注公众号，回复   
znlinux 即可下载！！！  
  
