# intrusion-detection-manually
手动检测是否被入侵
![image](https://github.com/dahailinux/intrusion-detection-manually/assets/54297681/f94340aa-2cda-47bb-9e95-282dc1fc2028)


入侵检测原理：	
1. 基于日志（Audit日志为主，监控系统调用，网络访问，新建进程，隐藏进程）	
2. 威胁情报（根据IP，文件，隐藏的文件，隐藏进程，suid文件）	
3. 文件完整性	
4. 命令审计，进程做的所有操作通过安全库进行判断；	
5. 病毒木马库（后门、Rootkit、病毒木马等）；	
	
	
Gitlab代码是否又被修改过，用gitdiff查看	查看代码的日志
代码是否有被改动过	
查看服务器日志	是否有被劫持
查看登录记录	查看非法sql语句执行记录
	
	
secure的登录日志，看有没有成功的异地IP登录	
用md5工具查看，是否有文件被修改过的	
看日志，是否有被删除，是否有异常日志	
看历史记录，	
看audit审计，是否执行了异常的syscall	
查看异常进程	
查看异常端口	
查看堡垒机日志，是否有异常操作，比如传输文件，比如安装程序；	
用NIDS查看，是否有网络异常行为，	
rpm -Va，看哪些包被替换了；	
看这台机器的外联IP，用tcpdump抓包	用威胁情报查看这个外联IP
tcpdump抓包一小时，用wireshark分析	
查看当前运行的内核模块	
查看一个可执行文件对应的库文件，是否正常	ldd，strace
查看dns日志记录，看是否有恶意的域名记录	
应用程序日志，被渗透日志	
find被渗透时间内被修改过的文件，然后分析这些文件	
服务器登录记录，tty等	
看运行了什么应用，各个应用的日志	
从防火墙上看到这台机器的网络连接日志	
用户信息文件/etc/passwd	
who，w，uptime看哪些用户在登陆	
查看特权用户，uid=0	
弱密码扫描一遍，所有应用和ssh	
基线检测扫描一遍	
看有没有重大漏洞，比如未授权等，漏洞扫描一遍	
more /etc/sudoers，看可以切换到root的用户	
/etc/profile	
.bash_profile	
.bashrc	
/etc/rc.d/rc.local	
/etc/rc.d/init.d	
/etc/rc.d/rc.sysinit	
 /etc/inittab	
vim /etc/cron里的每一个文件；	
ls /etc/rc.d/rc3.d	
/etc/rc.sysinit	
/etc/rc.d/所有	
/etc/fstab	
vim /etc/bashrc	
~/.bash_login	
~/.profile	
~/.bash_profile	
~/.xinitrc ~/.xserverrc	不允许有这个图形配置文件
/etc/init.d	查看是否有恶意脚本
ls /tmp	这里是高权限目录
cron日志，看自动任务都有什么	
/var/spool/cron/* 	看一下目录是否也有恶意脚本
/etc/crontab	
/etc/cron.d/*	
/etc/cron.daily/* 	
/etc/cron.hourly/* 	
/etc/cron.monthly/*	
/etc/cron.weekly/	
/etc/anacrontab	
/var/spool/anacron/*	
more /etc/cron.daily/*	查看目录下所有文件
扫描webshell	
看php的代码文件是否被修改过	
/var/log/cron	记录了系统定时任务相关的日志
/var/log/cups	记录打印信息的日志
/var/log/dmesg	记录了系统在开机时内核自检的信息，也可以使用dmesg命令直接查看内核自检信息
/var/log/mailog	记录邮件信息
/var/log/message	记录系统重要信息的日志。这个日志文件中会记录Linux系统的绝大多数重要信息，如果系统出现问题时，首先要检查的就应该是这个日志文件
/var/log/btmp	记录错误登录日志，这个文件是二进制文件，不能直接vi查看，而要使用lastb命令查看
/var/log/lastlog	记录系统中所有用户最后一次登录时间的日志，这个文件是二进制文件，不能直接vi，而要使用lastlog命令查看
/var/log/wtmp	永久记录所有用户的登录、注销信息，同时记录系统的启动、重启、关机事件。同样这个文件也是一个二进制文件，不能直接vi，而需要使用last命令来查看
/var/log/utmp	记录当前已经登录的用户信息，这个文件会随着用户的登录和注销不断变化，只记录当前登录用户的信息。同样这个文件不能直接vi，而要使用w,who,users等命令来查询
/var/log/secure	记录验证和授权方面的信息，只要涉及账号和密码的程序都会记录，比如SSH登录，su切换用户，sudo授权，甚至添加用户和修改用户密码都会记录在这个日志文件中
chkrootkit	rootkit检查一遍
rkhunter	
Clamav	
https://github.com/grayddq/GScan	安全检查脚本
https://github.com/ppabc/security_check	
https://github.com/T0xst/linux	
more /etc/sudoers	
查找所有suid和guid文件，find . -perm /2000	find . -perm /4000
/root/.ssh/authorized_keys	看谁能免密登陆我
/root/.ssh/known_hosts	谁成功登陆过我
看ssh进程	
ls -al /usr/sbin/sshd	
cat /usr/sbin/sshd	
alias	
stat /lib/security/pam_unix.so      #32位	
stat /lib64/security/pam_unix.so    #64位	
看/usr/sbin/nologin文件是否被修改，被修改成bash则证明所有用户能登录；	
查看所有的连接文件，看su或bash是否出现在不该出现的位置	
是否有这个文件/etc/ld.so.preload	
echo $LD_PRELOAD	
/usr/lib/ld.so	
unhide proc	用unhide工具找隐藏进程
查找所有隐藏文件	
/etc/profile、~/.bash_profile、~/.bash_login、~/.profile、~/.bashrc、/etc/bashrc、/etc/profile.d/*.sh	

木马后门排查路径

Linux后门就那么几种：
1. 反弹shell
2. 修改系统配置形成的后门；
3. 修改系统bin文件，隐藏的后门
4. 修改库文件，隐藏的后门
5. 内核态的rootkit；
6. 基于文件，新建进程的木马后门；
7

除了rootkit类似的隐藏木马，其他都能查出来；
木马都有自我恢复功能，在处理的时候，要一次性执行所有指令清除木马；
遍历Linux系统下的所有文件，并查看文件类型，用file指令，如果是elf类型的文件就输出，看他是不是异常的疑似木马；
crontab -l
/etc/crontab
/etc/profile ->/etc/enviroment -->$HOME/.profile -->$HOME/.env
/etc/init.d/
/etc/rc.d/init.d
/etc/rc.d/{init.d,rc{1,2,3,4,5}.d}/
/etc/rc.local
/etc/profile
/etc /bashrc
$HOME/.bash_profile
$HOME/.bashrc
$HOME/.bash_login
$HOME/.profile
~/.bash_logout
/tmp
/dev/shm
/etc/passwd

ps -ef看没用的进程
netstat -anplt 看没用的目标IP
看服务器支持什么开发语言，有什么应用，找应用对应数据目录下的脚本（尤其是用户上传目录和头像等目录）；
每个用户默认的家目录，因为他执行rce，只能在自己的家目录生效；
全盘查找elf类型的文件
last, lastlog
grep -i Accepted /var/log/secure
/var/spool/cron/
/etc/cron.hourly
/etc/crontab
find / -ctime 1
/usr/lib/systemd/system
/etc/systemd/system
chkconfig --list

检查/etc/passwd和/etc/shadow文件，是否有可疑用户
检查临时目录/tmp、/vat/tmp、/dev/shm，这些目录权限是1777，容易被上传木马文件
查看自启动的服务
pstree
lsof： 1. 进程使用的文件， 2. 文件被哪个进程使用，3. 使用某个端口的进程， 4. 系统打开的端口
iftop 监控每个socket使用的网络流量
nethogs 监控每个进程使用的网络流量
strings输出文件中可打印的字符
/var/spool/cron/root
/var/spool/cron/crontabs/root
/var/spool/anacron/cron.{daily，weekly，monthly}
/etc/anacrontab
如果有php防止是webshell


其余的杀毒软件，只能用在下线机器上，进行溯源使用：
clamav杀毒引擎、rkhunter、chkrootkit
find -type f -name *.php -exec chmod 444 {} ;
grep -r –include=*.php '[^a-z]eval($_POST' . > grep.txt
grep -r –include=*.php 'file_put_contents(。*$_POST[.*]);' . > grep.txt

后门查找
/etc/passwd
ssh公钥删除没用的
visudo
find / -perm /4000  找所有suid文件
防止ssh软连接，查找无用的开放端口
有可能把sshd等命令已经替换了，都替换成了带有后门的程序了。
有可能把库文件都给替换了；
w
uptime
last
lastlog
lastb
who
strings /usr/bin/.sshd | egrep '[1-9]{1,3}.[1-9]{1,3}.'
1、root的历史命令
histroy
2、打开/home各帐号目录下的.bash_history，查看普通帐号的历史命令
/var/log/secure
/var/log/message
/var/log/yum.log


执行last,lastlog命令，查看最近登录的账户和登录时间，锁定异常账户。
执行grep -i Accepted /var/log/secure命令，查看远程登录成功的IP地址。
执行以下命令，查找计划任务。
/var/spool/cron/
/etc/cron.hourly
/etc/crontab
执行find / -ctime 1通过文件状态最后修改时间来查找木马文件。
检查/etc/passwd和/etc/shadow文件，确认是否有可疑用户。
检查临时目录/tmp、/vat/tmp、/dev/shm下的文件，这些目录权限是1777，容易被上传木马文件。
查看端口对外的服务日志是否存在异常，例如：tomcat、nginx。
执行service --status-all | grep running，查看当前运行的服务中是否存在异常。
执行chkconfig --list | grep :on，查看自启动的服务中是否存在异常。
执行ls -lt /etc/init.d/ | head，查看是否有异常启动脚本

ps aux查看进程，是否有su、（无横杠-）的bash、chsh、chfn进程；
vim /root/.bashrc(所有用户下都看下)
alias 看一下这个显示有没有异常信息；
主要看文件md5值改变了就要注意；
vim /var/spool/cron/用户名  这个就是crontab -l调用的文件，必须用vim看，隐藏的任务是cat查不出来的；
/tmp下面的可疑文件全删，这里一般和业务没关系，但是权限是最大的目录。
把所有用户下的.ssh目录下的证书删除，只保留堡垒机等业务需要的；
cat /etc/ls.so.preload
cat /etc/ld.so.cache
echo $LD_AUDIT
echo $LD_PRELOAD
看/proc下的所有进程Id统计和ps -ef出来的不一样，就证明有隐藏进程；
vi /etc/hosts.allow 查看里面是否有恶意代码
清理/etc/passwd下，没有空密码的用户；
删除socat命令
