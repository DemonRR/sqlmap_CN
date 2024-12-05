<p align="center">
  <h1 align="center">SQLMAP 中文版</h1>
</p>

<p align="center">
<a href="https://github.com/DemonRR/sqlmap_CN/releases/"><img src="https://img.shields.io/github/release/DemonRR/sqlmap_CN?label=%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC&style=square"></a>
<a href="https://github.com/DemonRR/sqlmap_CN/releases"><img src="https://img.shields.io/github/downloads/DemonRR/sqlmap_CN/total?label=%E4%B8%8B%E8%BD%BD%E6%AC%A1%E6%95%B0&style=square"></a>
<a href="https://github.com/DemonRR/sqlmap_CN/issues"><img src="https://img.shields.io/github/issues-raw/DemonRR/sqlmap_CN?label=%E9%97%AE%E9%A2%98%E5%8F%8D%E9%A6%88&style=square"></a>
<a href="https://github.com/DemonRR/sqlmap_CN/discussions"><img src="https://img.shields.io/github/stars/DemonRR/sqlmap_CN?label=%E7%82%B9%E8%B5%9E%E6%98%9F%E6%98%9F&style=square"></a>
</p>


&emsp;&emsp;SQLMap 是一款开源的自动化 SQL 注入工具，用于检测和利用 Web 应用程序中的 SQL 注入漏洞，能够进行漏洞检测、数据库枚举、数据提取修改以及在特定情况下执行操作系统命令。

## 命令帮助

Usage: sqlmap.py [选项]

```
Options:
  -h, --help            Show basic help message and exit
  -hh                   显示高级帮助消息并退出
  --version             显示程序的版本号并退出
  -v VERBOSE            冗长级别: 0-6 (默认 1)
```

  目标:
    必须至少提供其中一个选项来定义目标

    -u URL, --url=URL   目标URL(例如 "http://www.site.com/vuln.php?id=1")
    -d DIRECT           连接字符串直接数据库连接
    -l LOGFILE          从Burp或WebScarab代理日志文件解析目标(s)
    -m BULKFILE         扫描多个目标在一个文本文件
    -r REQUESTFILE      从文件中加载HTTP请求
    -g GOOGLEDORK       将Google dork结果作为目标URLs处理
    -c CONFIGFILE       从一个配置加载选项INI文件

  请求:
    这些选项可用于指定如何连接到目标URL

    -A AGENT, --user..  HTTP User-Agent 标头值
    -H HEADER, --hea..  额外的标头 (例如 "X-Forwarded-For: 127.0.0.1")
    --method=METHOD     强制使用给定HTTP方法(例如 PUT)
    --data=DATA         通过POST发送的数据字符串(例如 "id=1")
    --param-del=PARA..  用于拆分参数值的字符(例如 &
    --cookie=COOKIE     HTTP Cookie头的值(例如 "PHPSESSID=a8d127e..")
    --cookie-del=COO..  用于拆分cookie值的字符(例如 ;)
    --live-cookies=L..  用于加载最新值的实时cookie文件
    --load-cookies=L..  包含Netscape/wget格式cookie的文件
    --drop-set-cookie   忽略响应中的Set Cookie标头
    --mobile            通过 HTTP User-Agent 标头模拟智能手机
    --random-agent      使用随机选择的 HTTP User-Agent 标头值
    --host=HOST         HTTP Host 标头值
    --referer=REFERER   HTTP Referer 标头值
    --headers=HEADERS   额外的标头 (e.g. "Accept-Language: fr\nETag: 123")
    --auth-type=AUTH..  HTTP身份验证类型 (Basic, Digest, Bearer, ...)
    --auth-cred=AUTH..  HTTP身份验证凭证 (name:password)
    --auth-file=AUTH..  HTTP身份验证PEM证书/私钥文件
    --abort-code=ABO..  在（有问题的）HTTP错误代码（例如 401）时中止
    --ignore-code=IG..  忽略（有问题的）HTTP错误代码（例如401）
    --ignore-proxy      忽略系统默认代理设置
    --ignore-redirects  忽略重定向的尝试
    --ignore-timeouts   忽略连接超时
    --proxy=PROXY       使用一个代理连接到目标URL
    --proxy-cred=PRO..  代理认证凭证（用户名:密码）
    --proxy-file=PRO..  从文件加载代理列表
    --proxy-freq=PRO..  请求改变之间的代理从一个给定的列表
    --tor               使用Tor匿名网络
    --tor-port=TORPORT  设置Tor代理端口,而不是默认值
    --tor-type=TORTYPE  设置Tor代理类型(HTTP、SOCKS4或SOCKS5(默认)
    --check-tor         查看是否正确使用Tor
    --delay=DELAY       每个HTTP请求之间的延迟（秒）
    --timeout=TIMEOUT   超时连接前等待的秒数(默认值 30)
    --retries=RETRIES   重试时连接超时(默认 3)
    --retry-on=RETRYON  对匹配内容的正则表达式重试请求(例如 "drop")
    --randomize=RPARAM  对于给定的参数随机变化值(s)
    --safe-url=SAFEURL  URL地址访问期间经常测试
    --safe-post=SAFE..  POST数据发送到一个安全的URL
    --safe-req=SAFER..  从一个文件装载安全的HTTP请求
    --safe-freq=SAFE..  定期请求访问一个安全的URL
    --skip-urlencode    跳过URL编码的有效载荷数据
    --csrf-token=CSR..  参数用于保存anti-CSRF令牌
    --csrf-url=CSRFURL  URL地址为提取anti-CSRF访问令牌
    --csrf-method=CS..  HTTP方法使用anti-CSRF标记页面访问期间
    --csrf-data=CSRF..  POST数据发送anti-CSRF标记页面访问期间
    --csrf-retries=C..  重试anti-CSRF令牌检索(默认 0)
    --force-ssl         强制使用SSL/HTTPS
    --chunked           使用HTTP分块传输编码(POST)请求
    --hpp               使用HTTP参数污染的方法
    --eval=EVALCODE     请求之前评估提供Python代码(例如 "import
                        hashlib;id2=hashlib.md5(id).hexdigest()")

  优化:
    这些选项可用于优化sqlmap的性能

    -o                  打开所有优化开关
    --predict-output    预测常见的查询输出
    --keep-alive        使用持久HTTP (s)连接
    --null-connection   检索页面长度没有实际的HTTP响应的身体
    --threads=THREADS   最大并发HTTP (s)请求(默认 1)

  注入:
    这些选项可用于指定要测试的参数、提供自定义注入有效载荷和可选的篡改脚本

    -p TESTPARAMETER    可测试参数
    --skip=SKIP         跳过测试对于给定参数(s)
    --skip-static       跳过测试参数不似乎是动态的
    --param-exclude=..  Regexp排除参数测试(例如 "ses")
    --param-filter=P..  选择测试的参数(s)的位置(例如 "POST")
    --dbms=DBMS         强制后端DBMS提供值
    --dbms-cred=DBMS..  DBMS身份验证凭据(用户:密码)
    --os=OS             强制后端DBMS操作系统提供价值
    --invalid-bignum    使用大量无效值
    --invalid-logical   使用逻辑操作无效值
    --invalid-string    使用随机字符串无效值
    --no-cast           关掉负载铸造机制
    --no-escape         关掉字符串转义机制
    --prefix=PREFIX     注入载荷前缀字符串
    --suffix=SUFFIX     注入载荷后缀字符串
    --tamper=TAMPER     使用给定的脚本(s)篡改注入数据

  侦查:
    这些选项可用于自定义检测阶段

    --level=LEVEL       要执行的测试的水平(1-5,默认 1)
    --risk=RISK         要执行的测试的风险(1-3,默认 1)
    --string=STRING     查询字符串来匹配时求值为True
    --not-string=NOT..  字符串匹配时查询计算为False
    --regexp=REGEXP     Regexp匹配查询时求值为True
    --code=CODE         HTTP代码查询评估为True时匹配
    --smart             进行彻底的测试只有在积极的启发式(s)
    --text-only         页面只基于文本内容进行比较
    --titles            比较页面仅基于他们的头衔

  技术:
    这些选项可用于调整特定SQL注入技术的测试

    --technique=TECH..  要使用的SQL注入技术(默认 "BEUSTQ")
    --time-sec=TIMESEC  秒延迟DBMS响应(默认 5)
    --union-cols=UCOLS  列的SQL注入的测试联合查询
    --union-char=UCHAR  字符用于bruteforcing列数
    --union-from=UFROM  UNION查询SQL注入的FROM部分中使用的表
    --union-values=U..  用于 UNION 查询 SQL 注入的列值
    --dns-domain=DNS..  域名用于DNS漏出攻击
    --second-url=SEC..  产生的页面的URL搜索二阶响应
    --second-req=SEC..  从文件加载二阶HTTP请求

  Fingerprint:
    -f, --fingerprint   执行一个广泛的DBMS版本指纹

  枚举:
    这些选项可用于枚举表中包含的后端数据库管理系统信息、结构和数据

    -a, --all           检索所有
    -b, --banner        检索DBMS横幅
    --current-user      获取当前用户数据库管理系统
    --current-db        检索DBMS当前数据库
    --hostname          检索DBMS服务器主机名
    --is-dba            检测是否DBA DBMS当前用户
    --users             列举DBMS用户
    --passwords         列举DBMS用户 password hashes
    --privileges        列举DBMS用户 privileges
    --roles             列举DBMS用户 roles
    --dbs               列举DBMS数据库
    --tables            列举DBMS数据库表
    --columns           列举DBMS数据库表列
    --schema            枚举DBMS模式
    --count             检索表(s)的条目数量
    --dump              转储DBMS数据库表条目
    --dump-all          转储所有DBMS数据库表条目
    --search            搜索列、表和/或数据库名称
    --comments          枚举期间检查DBMS注释
    --statements        检索SQL语句被运行在DBMS
    -D DB               数据库管理系统数据库来列举
    -T TBL              数据库管理系统数据库表(s)列举
    -C COL              数据库管理系统数据库表列(s)枚举
    -X EXCLUDE          数据库管理系统数据库标识符(s)不列举
    -U USER             DBMS用户列举
    --exclude-sysdbs    列举表时排除DBMS系统数据库
    --pivot-column=P..  主列名称
    --where=DUMPWHERE   使用条件而表倾销
    --start=LIMITSTART  第一个转储表条目检索
    --stop=LIMITSTOP    去年转储表条目检索
    --first=FIRSTCHAR   第一个查询输出单词字符检索
    --last=LASTCHAR     最后输出单词字符检索查询
    --sql-query=SQLQ..  要执行的SQL语句
    --sql-shell         提示一个交互式SQL壳
    --sql-file=SQLFILE  从给定的文件执行的SQL语句(s)

  蛮力破解:
    这些选项可用于运行暴力检查

    --common-tables     检查存在的常见的表
    --common-columns    检查是否存在共同的列
    --common-files      检查公共文件的存在

  用户定义函数注入:
    这些选项可用于创建自定义用户定义函数

    --udf-inject        注入自定义用户定义函数
    --shared-lib=SHLIB  共享库的本地路径

  文件系统访问:
    这些选项可用于访问后端数据库管理系统底层文件系统

    --file-read=FILE..  读取一个文件从文件系统后端数据库管理系统
    --file-write=FIL..  写一个本地文件的后端数据库管理系统的文件系统
    --file-dest=FILE..  后端DBMS绝对filepath写

  操作系统访问:
    这些选项可用于访问后端数据库管理系统底层操作系统

    --os-cmd=OSCMD      执行一个操作系统命令
    --os-shell          提示一个交互式操作系统shell
    --os-pwn            OOB shell提示,Meterpreter或VNC
    --os-smbrelay       一个点击提示OOB壳,Meterpreter或VNC
    --os-bof            存储过程缓冲区溢出exploitation
    --priv-esc          数据库处理用户特权升级
    --msf-path=MSFPATH  地方道路Metasploit框架安装
    --tmp-path=TMPPATH  远程临时文件目录的绝对路径

  Windows注册表访问:
    这些选项可用于访问后端数据库管理系统Windows注册表

    --reg-read          读一个Windows注册表键值
    --reg-add           写一个Windows注册表键值数据
    --reg-del           删除一个Windows注册表键值
    --reg-key=REGKEY    Windows注册表键
    --reg-value=REGVAL  Windows注册表键 value
    --reg-data=REGDATA  Windows注册表键 value data
    --reg-type=REGTYPE  Windows注册表键 value type

  全体的:
    这些选项可用于设置一些常规工作参数

    -s SESSIONFILE      从一个存储加载会话(.sqlite)文件
    -t TRAFFICFILE      记录所有HTTP流量到一个文本文件中
    --abort-on-empty    在结果为空时中止数据检索。
    --answers=ANSWERS   预定义的答案(例如 "quit=N,follow=N")
    --base64=BASE64P..  包含Base64编码数据的参数(年代)
    --base64-safe       使用URL和文件名安全Base64字母表(RFC 4648)
    --batch             从来没有要求用户输入,使用默认的行为
    --binary-fields=..  结果字段有二进制值(例如 "digest")
    --check-internet    检查网络连接之前评估的目标
    --cleanup           清理的DBMS sqlmap特定UDF和表
    --crawl=CRAWLDEPTH  爬行网站从目标URL
    --crawl-exclude=..  Regexp排除页面爬行(例如 "logout")
    --csv-del=CSVDEL    (CSV输出中使用的分隔字符 (默认 ",")
    --charset=CHARSET   盲SQL注入字符集(例如 "0123456789abcdef")
    --dump-file=DUMP..  将数据存储到一个自定义文件
    --dump-format=DU..  了数据的格式(CSV(默认)、HTML或SQLITE)
    --encoding=ENCOD..  字符编码用于数据检索(例如GBK)
    --eta               预计到达时间为每个输出显示
    --flush-session     冲洗会话文件当前的目标
    --forms             解析和测试目标URL形式
    --fresh-queries     忽略查询结果存储在会话文件中
    --gpage=GOOGLEPAGE  使用指定页码的Google dork结果
    --har=HARFILE       记录所有HTTP流量HAR文件
    --hex               在数据检索使用十六进制转换
    --output-dir=OUT..  自定义输出目录路径
    --parse-errors      从响应解析和显示DBMS的错误消息
    --preprocess=PRE..  使用给定的脚本(s)预处理(请求)
    --postprocess=PO..  使用给定的脚本(s)后处理(响应)
    --repair            Redump条目有未知字符标记(?)
    --save=SAVECONFIG   保存选项来配置INI文件
    --scope=SCOPE       Regexp过滤目标
    --skip-heuristics   跳过启发式检测漏洞
    --skip-waf          跳过WAF/IPS保护的启发式检测
    --table-prefix=T..  前缀用于临时表(默认值: "sqlmap")
    --test-filter=TE..  按有效载荷和/或标题选择测试(例如 ROW)
    --test-skip=TEST..  按有效载荷和/或标题跳过测试(例如 BENCHMARK)
    --time-limit=TIM..  以秒为单位的时间限制运行 (例如 3600)
    --unsafe-naming     禁用DBMS标识符的转义 (例如 "user")
    --web-root=WEBROOT  Web服务器的文档根目录(例如 "/var/www")

  混杂的:
    这些选项不属于任何其他类别

    -z MNEMONICS        使用短助记符(例如 "flu,bat,ban,tec=EU")
    --alert=ALERT       运行主机操作系统命令(s) SQL注入时发现
    --beep              出现问题和/或发现漏洞时发出蜂鸣声
    --dependencies      检查丢失(可选)sqlmap依赖性
    --disable-coloring  禁用控制台输出颜色
    --list-tampers      显示列表可用夯的脚本
    --no-logging        禁用日志记录到一个文件
    --offline           在离线模式下工作(只使用会话数据)
    --purge             从sqlmap数据目录中安全地删除所有内容
    --results-file=R..  在多个目标模式下结果CSV文件的位置
    --shell             提示一个交互式sqlmap shell
    --tmp-dir=TMPDIR    本地目录用于存储临时文件
    --unstable          调整选项不稳定的连接
    --update            更新sqlmap
    --wizard            为新手用户简单的向导界面
