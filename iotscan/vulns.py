# -*- coding: utf-8 -*-
"""漏洞规则引擎: 基于端口/Banner/探测结果/设备类型匹配 40+ 条 IoT 安全规则。

规则条件语法 (when):
    any_port: [23, ...]        任一端口开放
    ports_all: [80, 443]       所有端口均开放
    min_open_ports: 12         开放端口数 >= N
    banner: "22|regex"         指定端口 Banner 匹配 (scope 为端口号或 any)
    http_title: "regex"        任一 HTTP 标题匹配
    http_server: "regex"       任一 HTTP Server 头匹配
    http_dirlist: True         存在目录列表
    http_dangerous_methods: True  OPTIONS 暴露 PUT/DELETE
    web_no_https: True         有 HTTP 管理端口但无 HTTPS
    mqtt_anonymous: True       MQTT 允许匿名
    rtsp_open: True            RTSP 无需认证即可播放
    ftp_anonymous: True        FTP 允许匿名登录
    redis_unauth: True         Redis 未授权
    snmp_public: True          SNMP 默认社区字符串
    random_mac: True           MAC 为本地管理地址
    dev_type: "IP 摄像头"       设备类型 (支持列表)
"""
from __future__ import annotations

import re

from .utils import SEV_ORDER
from .fingerprint import is_random_mac

WEB_PORTS = {80, 81, 443, 591, 3000, 3128, 5000, 5001, 8000, 8008, 8009,
             8080, 8081, 8082, 8443, 8444, 8800, 8888, 9000, 9001, 9002}
HTTPS_PORTS = {443, 8443, 9443}

# ============================================================ 规则库
RULES: list[dict] = [
    # ---------------- 明文协议 / 服务暴露 ----------------
    dict(id="TELNET-OPEN", title="Telnet 服务开放（明文协议）",
         severity="high", category="服务暴露", cwe="CWE-319", cvss=7.5,
         when=dict(any_port=[23, 2323, 26]),
         desc="Telnet 以明文传输全部流量（含用户名密码），且是 Mirai 等物联网僵尸网络"
              "最常攻击的入口。局域网内任意主机均可嗅探凭据。",
         fix="在设备管理界面关闭 Telnet，改用 SSH；如厂商固件不支持，"
             "至少设置 16 位以上强密码并禁止 WAN 口访问该端口。",
         refs=["CWE-319", "Mirai 僵尸网络", "CERT VU#630996"]),

    dict(id="FTP-OPEN", title="FTP 服务开放（明文协议）",
         severity="medium", category="服务暴露", cwe="CWE-319", cvss=5.3,
         when=dict(any_port=[21]),
         desc="FTP 以明文传输凭据与文件内容，局域网内可被嗅探劫持。",
         fix="改用 SFTP/FTPS；如仅用于本地共享，限制为局域网且禁止匿名访问。",
         refs=["CWE-319"]),

    dict(id="FTP-ANON", title="FTP 允许匿名登录",
         severity="high", category="访问控制", cwe="CWE-287", cvss=7.5,
         when=dict(ftp_anonymous=True),
         desc="设备 FTP 服务接受 anonymous 匿名登录，任何人都可读写其中文件，"
              "可能泄露摄像头录像、配置文件等敏感数据。",
         fix="关闭 FTP 匿名登录，为账户设置独立强密码，并最小化共享目录权限。",
         refs=["CWE-287"]),

    dict(id="HTTP-ADMIN", title="管理界面使用未加密 HTTP",
         severity="medium", category="传输安全", cwe="CWE-319", cvss=5.9,
         when=dict(any_port=[80, 8080, 8081, 8000, 8008, 8009, 8888, 81]),
         desc="设备通过明文 HTTP 提供管理页面，同一网络下的攻击者可嗅探"
              "登录凭据、篡改页面或实施会话劫持。",
         fix="启用设备 HTTPS 管理（如有），或仅在可信内网访问；"
             "修改默认管理端口并启用管理页登录失败锁定。",
         refs=["CWE-319", "OWASP IoT Top-10 I3"]),

    dict(id="WEB-NO-HTTPS", title="Web 服务未提供 HTTPS 选项",
         severity="low", category="传输安全", cwe="CWE-319", cvss=3.7,
         when=dict(web_no_https=True),
         desc="该设备开放 HTTP 管理端口，但未发现任何 HTTPS 端口，"
              "全部管理流量均为明文。",
         fix="升级固件开启 HTTPS，或将设备置于独立 IoT VLAN 限制访问。",
         refs=["CWE-319"]),

    dict(id="HTTP-DANGER-METHODS", title="Web 服务启用危险 HTTP 方法",
         severity="medium", category="访问控制", cwe="CWE-650", cvss=6.5,
         when=dict(http_dangerous_methods=True),
         desc="OPTIONS 探测显示该 Web 服务允许 PUT/DELETE/MOVE 等方法，"
              "攻击者可上传恶意文件或篡改配置。",
         fix="在 Web 服务器配置中仅允许 GET/POST/HEAD，关闭 WebDAV 类方法。",
         refs=["CWE-650"]),

    dict(id="HTTP-DIRLIST", title="Web 目录列表暴露",
         severity="low", category="信息泄露", cwe="CWE-548", cvss=4.3,
         when=dict(http_dirlist=True),
         desc="Web 根目录可列出文件清单，攻击者可借此发现备份文件、"
              "配置导出、日志等敏感内容。",
         fix="关闭目录浏览（Options -Indexes / 关闭 autoindex）。",
         refs=["CWE-548"]),

    dict(id="FIRMWARE-EXPOSED", title="页面泄露固件/版本信息",
         severity="low", category="信息泄露", cwe="CWE-200", cvss=3.1,
         when=dict(http_title=r"(?i)firmware|version|build|v\d+\.\d+"),
         desc="设备页面标题包含固件/版本号，便于攻击者检索对应公开漏洞"
              "（CVE）并构造针对性攻击。",
         fix="关闭管理页面上的版本信息显示；保持固件为最新版本。",
         refs=["CWE-200"]),

    # ---------------- 物联网协议 ----------------
    dict(id="MQTT-ANON", title="MQTT Broker 允许匿名接入",
         severity="high", category="物联网协议", cwe="CWE-306", cvss=7.5,
         when=dict(mqtt_anonymous=True),
         desc="MQTT 代理未启用认证，攻击者可订阅 # 通配主题窃听全部智能"
              "设备数据（温控、门锁状态、摄像头事件），并向设备下发伪造指令。",
         fix="为 MQTT Broker 启用用户名/密码认证与 ACL 主题授权，"
             "非必要不监听 0.0.0.0，优先使用 8883 端口 + TLS。",
         refs=["CWE-306", "OWASP IoT Top-10 I5"]),

    dict(id="MQTT-PLAIN", title="MQTT 明文传输（无 TLS）",
         severity="medium", category="传输安全", cwe="CWE-319", cvss=5.3,
         when=dict(any_port=[1883]),
         desc="MQTT over TCP 未加密，LAN 内可嗅探主题与消息内容。",
         fix="迁移到 MQTTS(8883) 并加载受信任证书，禁用明文端口。",
         refs=["CWE-319"]),

    dict(id="COAP-EXPOSED", title="CoAP 端口暴露",
         severity="low", category="物联网协议", cwe="CWE-668", cvss=3.7,
         when=dict(any_port=[5683]),
         desc="CoAP(5683) 明文 UDP 服务暴露，可能被用于放大 DDoS 或"
              "未授权资源读写。",
         fix="确认业务必要性，启用 DTLS(5684) 或限制访问来源。",
         refs=["CWE-668"]),

    dict(id="RTSP-OPEN", title="RTSP 视频流未授权可播放",
         severity="high", category="视频监控", cwe="CWE-306", cvss=7.5,
         when=dict(rtsp_open=True),
         desc="摄像头 RTSP 流无需认证即可 DESCRIBE/播放，攻击者可直接"
              "窃取实时画面，隐私严重泄露。",
         fix="在摄像机设置中开启 RTSP 认证（Digest/Basic），"
             "修改默认的 rtsp:// 路径，并限制访问网段。",
         refs=["CWE-306", "OWASP IoT Top-10 I3"]),

    dict(id="RTSP-PORT", title="RTSP 端口暴露",
         severity="low", category="视频监控", cwe="CWE-668", cvss=3.1,
         when=dict(any_port=[554, 8554]),
         desc="RTSP 端口开放，需确认已启用认证（详见探测结果）。",
         fix="保持固件更新；如通过 NVR 集中管理，可关闭摄像机直连 RTSP。",
         refs=["CWE-668"]),

    dict(id="DVR-EXPOSED", title="DVR/NVR 私有管理端口暴露",
         severity="medium", category="视频监控", cwe="CWE-668", cvss=5.3,
         when=dict(any_port=[37777, 34567]),
         desc="大华等 DVR/NVR 私有协议端口开放，历史上存在多起未授权"
              "访问与认证绕过漏洞（CVE-2013-6117 等）。",
         fix="升级固件至最新；把 DVR 置于独立网段；关闭不用的 SDK 端口。",
         refs=["CVE-2013-6117", "CWE-668"]),

    # ---------------- 远程管理面暴露 ----------------
    dict(id="SSH-OPEN", title="SSH 服务开放",
         severity="low", category="服务暴露", cwe="CWE-668", cvss=2.6,
         when=dict(any_port=[22]),
         desc="设备开放 SSH，若使用密码认证存在被暴力破解风险；"
              "嵌入式设备默认密码是僵尸网络首要目标。",
         fix="改用密钥认证、禁用 root 登录、修改默认端口，"
             "并部署 fail2ban 类防爆破机制。",
         refs=["CWE-307"]),

    dict(id="SSH-OLD", title="SSH 服务版本过旧（存在已知漏洞）",
         severity="high", category="已知漏洞", cwe="CWE-1104", cvss=7.5,
         when=dict(banner=r"22|(OpenSSH_[1-6][.\-_]|OpenSSH_7\.[0-7][^0-9]"
                          r"|Dropbear_20(1[0-5]|16))"),
         desc="SSH 版本低于当前维护版本，存在用户名枚举(CVE-2018-15473)、"
              "SCP 客户端注入(CVE-2020-15778) 等公开漏洞。",
         fix="升级 OpenSSH >= 9.x / Dropbear >= 2020，或关闭不必要的 SSH。",
         refs=["CVE-2018-15473", "CVE-2020-15778", "CWE-1104"]),

    dict(id="SMB-OPEN", title="SMB 服务暴露",
         severity="high", category="服务暴露", cwe="CWE-668", cvss=7.8,
         when=dict(any_port=[445]),
         desc="445/SMB 暴露在局域网，历史上 EternalBlue(CVE-2017-0144) 等"
              "漏洞可直接导致远程代码执行；IoT 设备使用老旧 Samba 组件时风险更高。",
         fix="禁用 SMBv1；确认设备为最新固件；NAS 类设备限制 SMB 访问网段。",
         refs=["CVE-2017-0144", "CWE-668"]),

    dict(id="RDP-EXPOSED", title="RDP 远程桌面暴露",
         severity="high", category="服务暴露", cwe="CWE-668", cvss=8.1,
         when=dict(any_port=[3389]),
         desc="RDP 暴露存在 BlueKeep(CVE-2019-0708) 等严重漏洞，"
              "以及撞库/暴力破解风险。",
         fix="关闭 RDP 或仅监听内网地址，启用网络级认证(NLA)与双因素。",
         refs=["CVE-2019-0708", "CWE-668"]),

    dict(id="VNC-EXPOSED", title="VNC 远程控制暴露",
         severity="high", category="服务暴露", cwe="CWE-306", cvss=7.5,
         when=dict(any_port=[5900, 5901, 5902]),
         desc="VNC 常以弱密码/空密码运行，多起 IoT 僵尸网络（如 Mirai 变种）"
              "专门扫描 VNC 端口。",
         fix="设置强密码或关闭 VNC；限制来源 IP；改用 SSH 隧道访问。",
         refs=["CWE-306", "CVE-2006-2369"]),

    dict(id="TFTP-OPEN", title="TFTP 服务暴露",
         severity="high", category="服务暴露", cwe="CWE-306", cvss=7.5,
         when=dict(any_port=[69]),
         desc="TFTP 无认证，常被 ISP/厂商用于设备配置下发，可被读取或"
              "刷写固件。",
         fix="确认无配置下发需求后关闭 TFTP。",
         refs=["CWE-306"]),

    # ---------------- 数据库 / 中间件 / 云 API ----------------
    dict(id="DB-EXPOSED", title="数据库端口暴露",
         severity="high", category="服务暴露", cwe="CWE-668", cvss=7.5,
         when=dict(any_port=[1433, 3306, 5432, 27017]),
         desc="数据库服务直接监听局域网，默认配置常带弱口令，"
              "智能家居平台数据库泄露事件多由此引发。",
         fix="数据库只监听 127.0.0.1 或内网可信网段，启用强密码与 IP 白名单。",
         refs=["CWE-668"]),

    dict(id="REDIS-UNAUTH", title="Redis 未授权访问",
         severity="critical", category="访问控制", cwe="CWE-306", cvss=9.8,
         when=dict(redis_unauth=True),
         desc="Redis 无认证且监听外网地址时，攻击者可通过 CONFIG SET dir"
              " + bgsave 写入 SSH 公钥或计划任务，直接获得服务器权限，"
              "亦可执行 FLUSHALL 清空数据。",
         fix="设置 requirepass 强密码；绑定 127.0.0.1；"
             "禁用危险命令（CONFIG/FLUSHALL）；开启 protected-mode。",
         refs=["CVE-2015-4335", "CWE-306"]),

    dict(id="REDIS-PORT", title="Redis 端口暴露",
         severity="medium", category="服务暴露", cwe="CWE-668", cvss=5.3,
         when=dict(any_port=[6379]),
         desc="Redis 端口开放，需确认已启用认证。",
         fix="为 Redis 配置 ACL 与防火墙白名单。",
         refs=["CWE-668"]),

    dict(id="MEMCACHED-EXPOSED", title="Memcached 未授权访问",
         severity="high", category="访问控制", cwe="CWE-306", cvss=7.5,
         when=dict(any_port=[11211]),
         desc="Memcached 无认证设计，曾引发大规模 UDP 反射 DDoS，"
              "且缓存数据可被任意读取/篡改。",
         fix="绑定内网地址、启用 SASL 认证、关闭 UDP 端口。",
         refs=["CVE-2018-1000115", "CWE-306"]),

    dict(id="ELASTIC-EXPOSED", title="Elasticsearch HTTP 接口暴露",
         severity="high", category="信息泄露", cwe="CWE-200", cvss=7.5,
         when=dict(any_port=[9200, 9300]),
         desc="Elasticsearch 9100/9200 无认证即可查询全部索引，"
              "智能家居日志/位置数据可能被拖库。",
         fix="启用 X-Pack 安全认证或反向代理认证，绑定内网地址。",
         refs=["CWE-200"]),

    dict(id="DOCKER-API", title="Docker 远程 API 未授权",
         severity="critical", category="访问控制", cwe="CWE-306", cvss=9.8,
         when=dict(any_port=[2375]),
         desc="Docker API(2375) 无 TLS 无认证暴露，攻击者可创建特权容器"
              "挂载宿主根目录，等同于服务器完全沦陷——IoT 网关/边缘"
              "计算节点的高危配置。",
         fix="关闭 TCP 明文端口（或使用 2376 + TLS + 证书）;"
             "通过 Unix Socket 管理 Docker。",
         refs=["CWE-306"]),

    # ---------------- UPnP / 管理面 / 其他 ----------------
    dict(id="UPNP-EXPOSED", title="UPnP/SSDP 服务暴露",
         severity="medium", category="服务暴露", cwe="CWE-668", cvss=5.3,
         when=dict(any_port=[1900, 5000, 49152, 49153]),
         desc="UPnP 允许内网设备自动配置端口映射，CallStranger 等漏洞"
              "可被用于外网探测与 DDoS 放大，摄像头/路由器 UPnP 事件频发。",
         fix="在路由器关闭 UPnP；设备侧禁用不需要的 UPnP 服务。",
         refs=["CVE-2020-12695", "CWE-668"]),

    dict(id="TR069-EXPOSED", title="TR-069/CWMP 远程管理端口暴露",
         severity="medium", category="服务暴露", cwe="CWE-668", cvss=6.5,
         when=dict(any_port=[7547]),
         desc="TR-069 是运营商远程管理协议(CPE WAN Management Protocol)，"
              "存在认证绕过与 RCE 漏洞历史（CVE-2014-8361 等），"
              "不应暴露在用户局域网。",
         fix="家庭内网禁用 7547；确认该端口仅对运营商 ACS 服务器可达。",
         refs=["CVE-2014-8361", "CWE-668"]),

    dict(id="SNMP-PUBLIC", title="SNMP 使用默认 public 社区字符串",
         severity="high", category="访问控制", cwe="CWE-1188", cvss=7.5,
         when=dict(snmp_public=True),
         desc="SNMP community 为默认 public，任何人可读取设备完整信息"
              "（接口、路由表、固件版本），部分设备还可写参数。",
         fix="修改默认 community 为随机长字符串；使用 SNMPv3；"
             "关闭不必要的 SNMP。",
         refs=["CWE-1188"]),

    dict(id="DNS-OPEN", title="DNS 服务暴露",
         severity="medium", category="服务暴露", cwe="CWE-668", cvss=5.3,
         when=dict(any_port=[53]),
         desc="DNS 53 端口开放，若配置为开放解析器可被用于反射 DDoS 攻击，"
              "也可能被 DNS 劫持。",
         fix="路由器 DNS 仅对内网响应；确认未开启递归出口。",
         refs=["CWE-668"]),

    dict(id="PRINT-EXPOSED", title="打印服务暴露",
         severity="medium", category="服务暴露", cwe="CWE-200", cvss=5.3,
         when=dict(any_port=[631, 9100, 515]),
         desc="Raw/IPP 打印端口开放意味着同网段任意主机可向打印机发送"
              "打印任务（数据泄露风险）；部分打印机固件漏洞可被直接利用。",
         fix="启用打印机访问控制/认证；将打印机置于独立 VLAN；"
             "保持固件更新。",
         refs=["CWE-200"]),

    dict(id="ICS-PROTOCOL", title="工控协议端口暴露（Modbus/S7/EtherNet/IP）",
         severity="high", category="服务暴露", cwe="CWE-668", cvss=8.1,
         when=dict(any_port=[502, 102, 44818, 20000, 47808]),
         desc="检测到 Modbus/S7/EtherNet/IP 等工业控制协议端口。家庭"
              "网络中此类端口几乎不可能合法存在，通常意味着暴露的"
              "工控网关或被入侵设备。",
         fix="立即确认设备归属；将工控设备隔离至专用网段；"
             "关闭非必要协议端口。",
         refs=["CWE-668"]),

    dict(id="BOTNET-PORTS", title="已知僵尸网络常用端口开放",
         severity="high", category="僵尸网络", cwe="CWE-668", cvss=7.5,
         when=dict(any_port=[2323, 48101, 34567, 37777]),
         desc="2323/48101/34567/37777 等端口是 Mirai、Mozi 等僵尸网络"
              "扫描频率最高的端口，常见于被植入远控的木马。",
         fix="检查设备是否已感染僵尸网络（异常外联、固件被篡改）；"
             "升级固件、恢复出厂设置并修改全部默认密码。",
         refs=["Mirai", "Mozi", "CWE-668"]),

    dict(id="ADB-OPEN", title="ADB 调试端口开放",
         severity="critical", category="访问控制", cwe="CWE-489", cvss=9.8,
         when=dict(any_port=[5555]),
         desc="Android ADB 调试端口无认证暴露，攻击者可直接获得设备"
              "shell 权限，安装应用、读取数据，是电视/机顶盒被入侵的"
              "主要原因。",
         fix="关闭 ADB 调试（开发者选项）；仅在使用时临时开启。",
         refs=["CWE-489"]),

    dict(id="DEV-MANY-PORTS", title="开放端口过多（攻击面过大）",
         severity="medium", category="攻击面", cwe="CWE-693", cvss=4.8,
         when=dict(min_open_ports=12),
         desc="单台设备开放超过 12 个端口，违背 IoT 设备最小化服务原则，"
              "攻击面显著增大。",
         fix="关闭不需要的服务与端口；为 IoT 设备划分独立 VLAN。",
         refs=["CWE-693"]),

    # ---------------- Web 服务已知漏洞版本 ----------------
    dict(id="WEBSERVER-GOAHEAD", title="GoAhead Web 服务器（已知 RCE）",
         severity="critical", category="已知漏洞", cwe="CWE-306", cvss=9.8,
         when=dict(banner="any|goahead"),
         desc="GoAhead 是大量国产摄像头/DVR 内置的 Web 服务器，"
              "CVE-2017-17215 等漏洞允许通过 /SDK/webLanguage 接口未授权"
              "执行任意代码，互联网批量利用广泛。",
         fix="立即升级设备固件；关闭 80/8000 端口对不可信网段的访问。",
         refs=["CVE-2017-17215", "CVE-2017-16997"]),

    dict(id="WEBSERVER-BOA-OLD", title="Boa Web 服务器版本过旧",
         severity="high", category="已知漏洞", cwe="CWE-1104", cvss=7.5,
         when=dict(banner=r"any|boa/0\.9[0-4]"),
         desc="Boa 0.94.x 是 2002 年即停止维护的 Web 服务器，存在多个"
              "认证绕过与缓冲区溢出漏洞，是路由器/摄像头的常见内置组件。",
         fix="升级固件替换 Web 服务组件；限制管理端口访问来源。",
         refs=["CWE-1104", "Boa 历史漏洞"]),

    dict(id="WEBSERVER-LIGHTTPD-OLD", title="lighttpd 版本过旧",
         severity="medium", category="已知漏洞", cwe="CWE-1104", cvss=6.1,
         when=dict(banner=r"any|lighttpd/1\.4\.([0-2][0-9]|3[0-4])([^0-9]|$)"),
         desc="lighttpd <= 1.4.34 存在多个已知漏洞（CRLF 注入、"
              "fastcgi 本地提权等）。",
         fix="升级 lighttpd 至 >= 1.4.60 或更换受维护的 Web 服务器。",
         refs=["CVE-2014-2323", "CWE-1104"]),

    dict(id="WEBSERVER-CAMERA-WEBS", title="摄像头嵌入式 Web 服务器",
         severity="medium", category="已知漏洞", cwe="CWE-306", cvss=6.8,
         when=dict(banner="any|(app-webs|dnvrs-webs|net-surveillance|webs)"),
         desc="DNVRS-Webs/App-webs 等嵌入式 Web 服务器存在认证绕过"
              "与命令注入历史漏洞（海康/大华设备多发）。",
         fix="升级设备固件到最新版本；修改默认口令；必要时关闭 Web 管理。",
         refs=["CWE-306"]),

    dict(id="HNAP-EXPOSED", title="HNAP 接口暴露（已知 RCE 家族）",
         severity="high", category="已知漏洞", cwe="CWE-306", cvss=8.8,
         when=dict(banner="any|hnap|SOAPActions"),
         desc="HNAP(Home Network Administration Protocol) 存在大量"
              "D-Link 等路由器 RCE 漏洞（CVE-2015-2051 系列），"
              "SOAPAction 注入可直接执行命令。",
         fix="升级路由器固件；关闭 HNAP；修改默认管理凭据。",
         refs=["CVE-2015-2051", "CVE-2019-17621"]),

    dict(id="MULTICAST-DNSSD", title="mDNS/DN-SD 服务广播",
         severity="info", category="信息泄露", cwe="CWE-200", cvss=2.6,
         when=dict(any_port=[5353]),
         desc="设备通过组播广播自身服务，便于内网发现但也便于攻击者"
              "枚举资产。",
         fix="保持默认即可，注意 IoT 设备不应暴露管理服务到全网。",
         refs=["CWE-200"]),

    # ---------------- 资产识别信息 ----------------
    dict(id="RANDOM-MAC", title="随机 MAC / 本地管理地址",
         severity="info", category="信息泄露", cwe="CWE-200", cvss=1.0,
         when=dict(random_mac=True),
         desc="该 MAC 为本地管理地址（随机 MAC 或虚拟接口），无法通过"
              "OUI 识别厂商，需人工确认设备归属。",
         fix="在路由器 DHCP/ARP 表中为该设备绑定静态 IP 与备注名称。",
         refs=["CWE-200"]),

    dict(id="UNKNOWN-VENDOR", title="无法识别设备厂商",
         severity="info", category="信息泄露", cwe="CWE-200", cvss=1.0,
         when=dict(unknown_vendor=True),
         desc="未能通过 MAC OUI 或 Banner 识别设备厂商，"
              "无法评估其固件安全生命周期。",
         fix="查询设备机身标签/IP 登录页确认品牌，纳入资产清单并"
             "订阅厂商安全公告。",
         refs=["CWE-200"]),

    dict(id="NO-SERVICE", title="主机存活但未发现开放端口",
         severity="info", category="攻击面", cwe="CWE-693", cvss=1.0,
         when=dict(no_open_ports=True),
         desc="主机在线但本次扫描未发现开放 TCP 端口（可能使用了"
              "高位端口、UDP 服务或被防火墙过滤）。",
         fix="如需进一步确认，使用 --full 全端口模式或针对性 UDP 扫描。",
         refs=["CWE-693"]),
]

RULES_BY_ID = {r["id"]: r for r in RULES}


# ============================================================ 匹配引擎
def _banner_match(device: dict, scope: str, pattern: str) -> bool:
    """匹配服务 Banner; scope=any 时同时检索 HTTP Server 响应头。"""
    rx = re.compile(pattern, re.IGNORECASE)
    for port, svc in (device.get("services") or {}).items():
        if scope != "any" and str(port) != str(scope):
            continue
        if rx.search(svc.get("banner") or ""):
            return True
        if scope == "any":
            http_info = (svc.get("http") or {}) or {}
            if rx.search(str(http_info.get("server") or "")):
                return True
    return False


def _http_field_match(device: dict, field: str, pattern: str) -> bool:
    rx = re.compile(pattern, re.IGNORECASE)
    for entry in (device.get("probes", {}).get("http") or {}).values():
        if not entry:
            continue
        if rx.search(str(entry.get(field) or "")):
            return True
    return False


def _check(cond_key: str, cond_val, device: dict) -> bool:
    ports = set(device.get("open_ports") or [])
    if cond_key == "any_port":
        return bool(ports & set(cond_val))
    if cond_key == "ports_all":
        return bool(ports) and set(cond_val) <= ports
    if cond_key == "min_open_ports":
        return len(ports) >= cond_val
    if cond_key == "banner":
        scope, _, pattern = str(cond_val).partition("|")
        return _banner_match(device, scope, pattern)
    if cond_key == "http_title":
        return _http_field_match(device, "title", cond_val)
    if cond_key == "http_server":
        return _http_field_match(device, "server", cond_val)
    if cond_key == "http_dirlist":
        return any(e and e.get("dirlist")
                   for e in (device.get("probes", {}).get("http") or {}).values())
    if cond_key == "http_dangerous_methods":
        return any(e and e.get("dangerous_methods")
                   for e in (device.get("probes", {}).get("http") or {}).values())
    if cond_key == "web_no_https":
        return bool(ports & WEB_PORTS) and not (ports & HTTPS_PORTS)
    checks = device.get("probes", {}).get("checks") or {}
    if cond_key in ("mqtt_anonymous", "rtsp_open", "ftp_anonymous",
                    "redis_unauth", "snmp_public"):
        return checks.get(cond_key) is cond_val
    if cond_key == "random_mac":
        return bool(is_random_mac(device.get("mac")))
    if cond_key == "unknown_vendor":
        return (device.get("vendor") or "未知厂商") == "未知厂商"
    if cond_key == "no_open_ports":
        return not ports
    return False


def evaluate(device: dict) -> list[dict]:
    """对单台设备执行全部规则, 返回 finding 列表(按严重级排序)。"""
    findings: list[dict] = []
    for rule in RULES:
        conds = rule.get("when") or {}
        if conds and all(_check(k, v, device) for k, v in conds.items()):
            findings.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "category": rule.get("category", "其他"),
                "cwe": rule.get("cwe"),
                "cvss": rule.get("cvss"),
                "description": rule["desc"],
                "recommendation": rule["fix"],
                "refs": rule.get("refs", []),
            })
    findings.sort(key=lambda f: SEV_ORDER.index(f["severity"]))
    return findings


def rule_catalog() -> list[dict]:
    """导出全部规则目录 (--list-rules 使用)。"""
    return RULES



