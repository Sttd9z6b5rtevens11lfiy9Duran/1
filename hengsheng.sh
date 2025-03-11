#!/usr/bin/env bash

# 设置 PATH 环境变量
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 切换到脚本所在目录
cd "$(
    cd "$(dirname "$0")" || exit 1
    pwd
)" || exit 1

# 定义颜色
Green="\033[32m"
Red="\033[31m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

# 加载系统信息
source '/etc/os-release'

# 定义提示信息
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

# 检查系统类型和版本
check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${Green} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        yum remove firewalld -y
        yum install -y iptables-services
        iptables -F
        iptables -t filter -F
        systemctl enable iptables.service
        service iptables save
        systemctl start iptables.service
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${Green} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        apt update
        for pkg in curl wget lsof; do
            if ! which "$pkg" > /dev/null; then
                apt install -y "$pkg"
            else
                echo -e "${OK} ${Green} $pkg 已安装 ${Font}"
            fi
        done
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${Green} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        apt update
        for pkg in curl wget lsof; do
            if ! which "$pkg" > /dev/null; then
                apt install -y "$pkg"
            else
                echo -e "${OK} ${Green} $pkg 已安装 ${Font}"
            fi
        done
        systemctl disable ufw.service
        systemctl stop ufw.service
    else
        echo -e "${Error} ${Red} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi
}

# 检查是否为 root 用户
is_root() {
    if [ "$UID" -eq 0 ]; then
        echo -e "${OK} ${Green} 当前用户是 root 用户，进入安装流程 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${Red} 当前用户不是 root 用户，请使用 'sudo -i' 切换到 root 用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

# 判断命令执行结果
judge() {
    if [[ $? -eq 0 ]]; then
        echo -e "${OK} ${Green} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${Red} $1 失败 ${Font}"
        exit 1
    fi
}

# 系统优化设置
sic_optimization() {
    # 设置最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >> /etc/security/limits.conf
    echo '* hard nofile 65536' >> /etc/security/limits.conf

    # 关闭 SELinux（仅 CentOS）
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0 2>/dev/null || true
    fi
}

# 设置固定端口
port_set() {
    port=6688
}

# 检查端口是否被占用
port_exist_check() {
    if [[ 0 -eq $(lsof -i:"${port}" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${Green} 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${Red} 检测到 ${port} 端口被占用，以下为 ${port} 端口占用信息 ${Font}"
        lsof -i:"${port}"
        echo -e "${OK} ${Green} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"${port}" | awk '{print $2}' | grep -v "PID" | xargs kill -9 2>/dev/null || true
        echo -e "${OK} ${Green} kill 完成 ${Font}"
        sleep 1
    fi
}

# 设置固定用户名和密码
user_set() {
    user="hengsheng"
    passwd="wangluo"
}

# 安装 SOCKS5 服务
install_ss5() {
    if [ -f "/usr/local/bin/socks" ]; then
        chmod +x /usr/local/bin/socks
    else
        echo -e "${Green} 正在下载 SOCKS5 二进制文件，请确保源可信 ${Font}"
        wget -O /usr/local/bin/socks --no-check-certificate https://github.com/kissyouhunter/Tools/raw/main/VPS/socks
        judge "下载 SOCKS5 二进制文件"
        chmod +x /usr/local/bin/socks
    fi

    cat <<EOF > /etc/systemd/system/sockd.service
[Unit]
Description=Socks Service
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/socks run -config /etc/socks/config.yaml
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sockd.service &>/dev/null
}

# 配置 SOCKS5
config_install() {
    mkdir -p /etc/socks
    cat <<EOF > /etc/socks/config.yaml
{
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "AsIs"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": "$port",
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [
                    {
                        "user": "$user",
                        "pass": "$passwd"
                    }
                ],
                "udp": true
            },
            "streamSettings": {
                "network": "tcp"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF
    systemctl start sockd.service
    judge "启动 SOCKS5 服务"
}

# 输出连接信息
connect() {
    IP=$(curl -s ipv4.ip.sb || echo "无法获取 IP")
    echo "IP: $IP"
    echo "端口: $port"
    echo "账户: $user"
    echo "密码: $passwd"
    echo "$IP:$port:$user:$passwd"
    echo -e "\nIP: $IP\n端口: $port\n账户: $user\n密码: $passwd\n$IP:$port:$user:$passwd" > /root/ss5.txt
}

# 安装 SOCKS5
s5_install() {
    sic_optimization
    port_set
    port_exist_check
    user_set
    install_ss5
    config_install
    connect
    systemctl restart sockd.service
    judge "安装 SOCKS5"
}

# 删除 SOCKS5
s5_del() {
    systemctl stop sockd.service
    rm -rf /usr/local/bin/socks
    rm -rf /etc/systemd/system/sockd.service
    systemctl daemon-reload
    rm -rf /etc/socks
    judge "删除 SOCKS5"
}

# 更新 SOCKS5 配置
s5_update() {
    port_set
    port_exist_check
    user_set
    rm -rf /etc/socks/config.yaml
    config_install
    systemctl restart sockd.service
    connect
    judge "更新 SOCKS5 配置"
}

# 主执行流程
is_root
check_system
s5_install
