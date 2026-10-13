# IoT Security Scanner · 物联网设备安全扫描器

一个**零第三方依赖**（纯 Python 标准库）的物联网设备安全扫描器：自动发现局域网内存活的
IoT 设备，识别开放端口、服务指纹、已知漏洞与**出厂默认凭据**，给出逐项修复建议，
并生成带图表的 HTML / JSON 安全报告。内置**酒店隐私模式**，出差住宿时排查房间网络里的
偷拍摄像头。

帮助你回答三个问题：

1. **我家里/办公室里到底连了哪些"幽灵设备"？**（含厂商、设备类型、主机名）
2. **哪些设备正在"裸奔"？**（Telnet 明文、无认证摄像头、匿名 MQTT、Redis 未授权……）
3. **我住的房间里有摄像头在看我吗？**（酒店隐私模式：组播发现 + 摄像头指纹 + 物理排查清单）

---

## 功能特性

| 阶段 | 能力 |
| --- | --- |
| 主机发现 | ICMP Ping 扫荡 + TCP 保活探测 + ARP 表合并 + 主机名解析（mDNS/NBNS/DNS） |
| 端口扫描 | 多线程 TCP 连接扫描，85 个 IoT 常用端口（top）/ 全 1024 端口（--full）/ 自定义 |
| 服务指纹 | MAC OUI 厂商识别（IEEE MA-L 官方注册表 10568 条）、Banner 抓取、设备类型推断 |
| 深度探测 | HTTP（标题/Server/目录列表/危险方法）、MQTT 匿名、RTSP 免认证播放、FTP 匿名、Redis 未授权、SNMP public、HTTPS 证书 |
| 组播发现 | ONVIF WS-Discovery（239.255.255.250:3702）、SSDP M-SEARCH 主动发现局域网摄像头 |
| 漏洞规则 | 44 条规则，覆盖明文协议、摄像头、物联网协议、默认/弱口令、已知 CVE、僵尸网络端口、工控协议、攻击面收敛 |
| 凭据检测 | 22 组常见出厂默认口令（Telnet / HTTP Basic / FTP），`--creds` 开启 |
| 风险评分 | 100 分扣减法 + A–F 评级，单品/全网双视角 |
| 报告输出 | 彩色控制台报告、独立 HTML 报告（仪表盘/环形图/排名/修复清单）、JSON 机读报告 |

### 规则引擎覆盖（44 条选摘）

- **严重**：Redis 未授权访问、ADB 调试端口、Docker API 未授权、**设备默认凭据**、GoAhead Web 服务器 RCE
- **高危**：Telnet 明文、RTSP 无认证播放、SMB/RDP/VNC 暴露、SSH 旧版本、MQTT 匿名、
  SNMP public、DVR 僵尸网络端口、Boa 旧版 Web 服务器、HNAP RCE、工控协议端口
- **中危**：HTTP 管理面明文、UPnP、TR-069、FTP/数据库/打印服务暴露、DVR 私有端口、Memcached
- **低危 / 提示**：无 HTTPS、目录列表、固件版本泄露、随机 MAC、厂商不可识别

---

## 快速开始

环境要求：Python 3.9+（Windows / Linux / macOS 均可用），**无需 pip install 任何包**。

```bash
# 1. 离线演示（无需网络，内置 12 台模拟智能家居设备）
python iotscan.py --demo

# 2. 酒店隐私模式演示（内置含针孔摄像头的模拟酒店房间网络）
python iotscan.py --hotel-demo

# 3. 扫描本机所在网段
python iotscan.py

# 4. 指定网段 / 单台设备
python iotscan.py -t 192.168.1.0/24
python iotscan.py -t 192.168.1.50

# 5. 含默认凭据测试 + 每台设备详情（建议用于自有设备）
python iotscan.py -t 192.168.1.0/24 --creds -v

# 6. 住酒店连上 WiFi 后排查房间摄像头
python iotscan.py --hotel --creds=false -v

# 7. 自定义端口并生成报告
python iotscan.py -t 192.168.1.0/24 --ports 80,443,554,8080 -o myreport
```

## 命令行参数

```
-t, --target    扫描目标: CIDR / 单 IP; 缺省自动探测本机网段
--ports         端口清单: top(默认) | 1-1024 | 80,443,554
--full          扫描 1024 低位端口 + 全部 IoT 端口
--timeout       单端口连接超时秒数 (默认 0.6)
--threads       并发线程数 (默认 128)
--creds         测试出厂默认凭据 (Telnet/HTTP Basic/FTP)
--demo          离线演示模式
--html PATH     HTML 报告路径 (默认 reports/iot-scan-时间戳.html)
--json PATH     JSON 报告路径 (默认 reports/iot-scan-时间戳.json)
-o, --outdir    报告输出目录 (默认 reports/)
-v, --verbose   输出每台设备的漏洞详情与修复建议
-q, --quiet     静默模式
--list-rules    列出全部 44 条检测规则
```

## 输出示例

```
 全网安全评分: 29/100 (E 级)
 发现风险: 49 项  严重 6 / 高危 11 / 中危 19 / 低危 13 / 提示 0

── 设备风险排名 (风险从高到低) ──
 IP              设备类型        厂商                      评分 等级  风险项
 192.168.1.106   DVR/NVR 录像机  大华 Dahua                0    F     10 项
 192.168.1.150   IoT 模组/开发板 乐鑫                      11   F     7 项
 192.168.1.101   IP 摄像头       海康威视 Hikvision        16   F     7 项
 ...
```

HTML 报告包含：全网安全评分仪表盘、漏洞严重级环形图、设备风险排名条形图、
优先修复清单、逐设备详情卡片（端口、指纹、漏洞说明与修复建议）。

## 项目结构

```
iot-scanner/
├── iotscan.py              # 命令行入口
├── iotscan/                # 核心包
│   ├── __init__.py
│   ├── utils.py            # 颜色输出/网段探测/ping/ARP
│   ├── discovery.py        # 主机发现
│   ├── portscan.py         # 端口扫描 + Banner 抓取
│   ├── fingerprint.py      # MAC OUI 厂商识别 + 设备类型推断
│   ├── probes.py           # HTTP/MQTT/RTSP/FTP/Redis/SNMP 深度探测
│   ├── vulns.py            # 44 条漏洞规则 + 匹配引擎
│   ├── creds.py            # 默认凭据检测 (opt-in)
│   ├── scoring.py          # 风险评分模型
│   ├── report.py           # 控制台/JSON/HTML 报告
│   └── core.py             # 扫描编排 + 演示数据
├── data/oui.json           # IEEE MA-L 厂商数据库 (10568 条)
├── tools/build_oui.py      # OUI 数据库生成/更新脚本
└── reports/                # 报告输出目录
```

## 更新 OUI 厂商数据库

`data/oui.json` 由 IEEE 官方注册表生成。需要更新新出厂设备时：

```bash
curl -sL https://standards-oui.ieee.org/oui/oui.csv -o oui.csv
python tools/build_oui.py oui.csv
```

## 酒店隐私模式（出差防偷拍）

住酒店/民宿时，连上房间 WiFi 后运行：

```bash
python iotscan.py --hotel          # 真实扫描
python iotscan.py --hotel-demo      # 演示（内置模拟酒店房间数据）
```

与家用漏洞扫描的区别：不评估"设备有没有漏洞"，而是评估"**网络里有没有摄像头可能在看我**"。

**检测手段（三层）**

1. **组播主动发现**：ONVIF WS-Discovery + SSDP 探测——摄像头无论端口怎么改，
   只要协议在线就会应答，这是发现隐藏 IPC/NVR 最可靠的一招；
2. **摄像头指纹**：RTSP/DVR/ONVIF 端口、摄像头厂商 OUI 与 Banner、免认证视频流；
3. **异常画像**：无法识别厂商 + Web 管理口、随机 MAC、端口画像与常见消费电子不匹配
   （廉价针孔摄像头的典型特征），同时对手机/电视/音箱等设备降权防误报。

**输出**：可疑度评分（高度可疑/可疑/常规）+ 每台可疑设备的证据链 + 8 步物理排查清单
（红光测试、镜头反光、双面镜、小孔排查、RF 探测等），HTML 报告同平面展示。

**诚实的能力边界**：只扫描**接入网络**的摄像头；**存本地卡、不入网**的针孔摄像头
网络扫描无法发现——这也是物理排查清单存在的意义。发现可疑设备后请保留证据、联系酒店、
必要时报警，不要自行拆除。

## 常见家庭网络安全加固清单

1. 路由器管理页改强密码 + 关 WAN 口远程管理，关闭 UPnP；
2. 摄像头/DVR：改默认口令、开 RTSP 认证、关 Telnet，及时升固件；
3. 智能音箱/家居中枢：只保留云端服务，关闭本地调试端口；
4. NAS：关 SMBv1、限定 SMB 访问网段、数据库不监听 0.0.0.0；
5. 划分 IoT 专用 VLAN/访客网络，与电脑手机隔离；
6. 每季度重扫一次，对照报告逐项销项。
