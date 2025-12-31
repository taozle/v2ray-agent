#!/usr/bin/env bash
# 检测区
# -------------------------------------------------------------
# 检查系统
export LANG=en_US.UTF-8

echoContent() {
    case $1 in
    # 红色
    "red")
        # shellcheck disable=SC2154
        ${echoType} "\033[31m${printN}$2 \033[0m"
        ;;
        # 天蓝色
    "skyBlue")
        ${echoType} "\033[1;36m${printN}$2 \033[0m"
        ;;
        # 绿色
    "green")
        ${echoType} "\033[32m${printN}$2 \033[0m"
        ;;
        # 白色
    "white")
        ${echoType} "\033[37m${printN}$2 \033[0m"
        ;;
    "magenta")
        ${echoType} "\033[31m${printN}$2 \033[0m"
        ;;
        # 黄色
    "yellow")
        ${echoType} "\033[33m${printN}$2 \033[0m"
        ;;
    esac
}
# 检查SELinux状态
checkCentosSELinux() {
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" == "Enforcing" ]; then
        echoContent yellow "# 注意事项"
        echoContent yellow "检测到SELinux已开启，请手动关闭，教程如下"
        echoContent yellow "https://www.v2ray-agent.com/archives/1684115970026#centos-%E5%85%B3%E9%97%ADselinux"
        exit 0
    fi
}
checkSystem() {
    if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
        mkdir -p /etc/yum.repos.d

        if [[ -f "/etc/centos-release" ]]; then
            centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

            if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
                centosVersion=8
            fi
        fi

        release="centos"
        installType='yum -y install'
        removeType='yum -y remove'
        #        upgrade="yum update -y --skip-broken"
        checkCentosSELinux
    elif { [[ -f "/etc/issue" ]] && grep -qi "Alpine" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "Alpine" /proc/version; }; then
        release="alpine"
        installType='apk add'
        upgrade="apk update"
        removeType='apk del'
        nginxConfigPath=/etc/nginx/http.d/
    elif { [[ -f "/etc/issue" ]] && grep -qi "debian" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "debian" /proc/version; } || { [[ -f "/etc/os-release" ]] && grep -qi "ID=debian" /etc/issue; }; then
        release="debian"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'

    elif { [[ -f "/etc/issue" ]] && grep -qi "ubuntu" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "ubuntu" /proc/version; }; then
        release="ubuntu"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        if grep </etc/issue -q -i "16."; then
            release=
        fi
    fi

    if [[ -z ${release} ]]; then
        echoContent red "\n本脚本不支持此系统，请将下方日志反馈给开发者\n"
        echoContent yellow "$(cat /etc/issue)"
        echoContent yellow "$(cat /proc/version)"
        exit 0
    fi
}

# 检查CPU提供商
checkCPUVendor() {
    if [[ -n $(which uname) ]]; then
        if [[ "$(uname)" == "Linux" ]]; then
            case "$(uname -m)" in
            'amd64' | 'x86_64')
                warpRegCoreCPUVendor="main-linux-amd64"
                singBoxCoreCPUVendor="-linux-amd64"
                ;;
            'armv8' | 'aarch64')
                cpuVendor="arm"
                warpRegCoreCPUVendor="main-linux-arm64"
                singBoxCoreCPUVendor="-linux-arm64"
                ;;
            *)
                echo "  不支持此CPU架构--->"
                exit 1
                ;;
            esac
        fi
    else
        echoContent red "  无法识别此CPU架构，默认amd64、x86_64--->"
    fi
}

# 初始化全局变量
initVar() {
    installType='yum -y install'
    removeType='yum -y remove'
    upgrade="yum -y update"
    echoType='echo -e'
    #    sudoCMD=""

    # 核心支持的cpu版本
    warpRegCoreCPUVendor=""
    cpuVendor=""

    # 域名
    domain=
    # 安装总进度
    totalProgress=1

    # 核心安装类型
    coreInstallType=
    # 1.全部安装
    # 2.个性化安装
    # v2rayAgentInstallType=

    # 当前的个性化安装方式 01234
    currentInstallProtocolType=

    # 当前alpn的顺序
    currentAlpn=

    # 前置类型
    frontingType=

    # 选择的个性化安装方式
    selectCustomInstallType=

    # 配置文件的路径
    configPath=

    # sing-box配置文件路径
    singBoxConfigPath=

    # sing-box端口

    singBoxVLESSVisionPort=
    singBoxVLESSRealityVisionPort=
    singBoxVLESSRealityGRPCPort=
    singBoxHysteria2Port=
    singBoxTrojanPort=
    singBoxTuicPort=
    singBoxNaivePort=
    singBoxVMessWSPort=
    singBoxVLESSWSPort=
    singBoxVMessHTTPUpgradePort=

    # nginx订阅端口
    subscribePort=

    subscribeType=

    # sing-box reality serverName publicKey
    singBoxVLESSRealityGRPCServerName=
    singBoxVLESSRealityVisionServerName=
    singBoxVLESSRealityPublicKey=
    # 端口跳跃
    portHoppingStart=
    portHoppingEnd=
    portHopping=

    hysteria2PortHoppingStart=
    hysteria2PortHoppingEnd=
    hysteria2PortHopping=

    #    tuicPortHoppingStart=
    #    tuicPortHoppingEnd=
    #    tuicPortHopping=

    # tuic配置文件路径
    #    tuicConfigPath=
    tuicAlgorithm=
    tuicPort=

    # 配置文件的path
    currentPath=

    # 配置文件的host
    currentHost=

    # 安装时选择的core类型
    selectCoreType=

    # 默认core版本
    #    v2rayCoreVersion=

    # 随机路径
    customPath=

    # centos version
    centosVersion=

    # UUID
    currentUUID=

    # clients
    currentClients=

    # previousClients
    #    previousClients=

    localIP=

    # 定时任务执行任务名称 RenewTLS-更新证书 UpdateGeo-更新geo文件
    cronName=$1

    # tls安装失败后尝试的次数
    installTLSCount=

    # BTPanel状态
    #	BTPanelStatus=
    # 宝塔域名
    btDomain=
    # nginx配置文件路径
    nginxConfigPath=/etc/nginx/conf.d/
    nginxStaticPath=/usr/share/nginx/html/

    # 是否为预览版
    prereleaseStatus=false

    # ssl类型
    sslType=
    # SSL CF API Token
    cfAPIToken=

    # ssl邮箱
    sslEmail=

    # 检查天数
    sslRenewalDays=90

    # dns ssl状态
    #    dnsSSLStatus=

    # dns tls domain
    dnsTLSDomain=
    ipType=

    # 该域名是否通过dns安装通配符证书
    #    installDNSACMEStatus=

    # 自定义端口
    customPort=

    # hysteria端口
    hysteriaPort=

    # hysteria协议
    #    hysteriaProtocol=

    # hysteria延迟
    #    hysteriaLag=

    # hysteria下行速度
    hysteria2ClientDownloadSpeed=

    # hysteria上行速度
    hysteria2ClientUploadSpeed=

    # Reality
    realityPrivateKey=
    realityServerName=
    realityDestDomain=

    # 端口状态
    #    isPortOpen=
    # 通配符域名状态
    #    wildcardDomainStatus=
    # 通过nginx检查的端口
    #    nginxIPort=

    # wget show progress
    wgetShowProgressStatus=

    # warp
    reservedWarpReg=
    publicKeyWarpReg=
    addressWarpReg=
    secretKeyWarpReg=

    # 上次安装配置状态
    lastInstallationConfig=

}

# 读取tls证书详情
readAcmeTLS() {
    local readAcmeDomain=
    if [[ -n "${currentHost}" ]]; then
        readAcmeDomain="${currentHost}"
    fi

    if [[ -n "${domain}" ]]; then
        readAcmeDomain="${domain}"
    fi

    dnsTLSDomain=$(echo "${readAcmeDomain}" | awk -F "." '{$1="";print $0}' | sed 's/^[[:space:]]*//' | sed 's/ /./g')
    if [[ -d "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.key" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer" ]]; then
        installedDNSAPIStatus=true
    fi
}

# 读取默认自定义端口
readCustomPort() {
    :
}

# 读取nginx订阅端口
readNginxSubscribe() {
    subscribeType="https"
    if [[ -f "${nginxConfigPath}subscribe.conf" ]]; then
        if grep -q "sing-box" "${nginxConfigPath}subscribe.conf"; then
            subscribePort=$(grep "listen" "${nginxConfigPath}subscribe.conf" | awk '{print $2}')
            subscribeDomain=$(grep "server_name" "${nginxConfigPath}subscribe.conf" | awk '{print $2}')
            subscribeDomain=${subscribeDomain//;/}
            if [[ -n "${currentHost}" && "${subscribeDomain}" != "${currentHost}" ]]; then
                subscribePort=
                subscribeType=
            else
                if ! grep "listen" "${nginxConfigPath}subscribe.conf" | grep -q "ssl"; then
                    subscribeType="http"
                fi
            fi

        fi
    fi
}

# 检测安装方式
readInstallType() {
    coreInstallType=
    configPath=
    singBoxConfigPath=

    # 检测安装目录
    if [[ -d "/etc/v2ray-agent" ]]; then
        if [[ -f "/etc/v2ray-agent/sing-box/sing-box" && -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
            # 检测sing-box
            ctlPath=/etc/v2ray-agent/sing-box/sing-box
            coreInstallType=2
            configPath=/etc/v2ray-agent/sing-box/conf/config/
            singBoxConfigPath=/etc/v2ray-agent/sing-box/conf/config/
        fi
    fi
}

# 读取协议类型
readInstallProtocolType() {
    currentInstallProtocolType=
    frontingType=

    currentRealityPrivateKey=
    currentRealityPublicKey=

    singBoxVLESSVisionPort=
    singBoxHysteria2Port=
    singBoxTrojanPort=

    frontingTypeReality=
    singBoxVLESSRealityVisionPort=
    singBoxVLESSRealityVisionServerName=
    singBoxVLESSRealityGRPCPort=
    singBoxVLESSRealityGRPCServerName=
    singBoxAnyTLSPort=
    singBoxTuicPort=
    singBoxNaivePort=
    singBoxVMessWSPort=
    singBoxSocks5Port=

    while read -r row; do
        if echo "${row}" | grep -q VLESS_TCP_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}0,"
            frontingType=02_VLESS_TCP_inbounds
            if [[ "${coreInstallType}" == "2" ]]; then
                singBoxVLESSVisionPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VLESS_WS_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}1,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=03_VLESS_WS_inbounds
                singBoxVLESSWSPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q trojan_gRPC_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}2,"
        fi
        if echo "${row}" | grep -q VMess_WS_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}3,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=05_VMess_WS_inbounds
                singBoxVMessWSPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q trojan_TCP_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}4,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=04_trojan_TCP_inbounds
                singBoxTrojanPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}5,"
        fi
        if echo "${row}" | grep -q hysteria2_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}6,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=06_hysteria2_inbounds
                singBoxHysteria2Port=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VLESS_vision_reality_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}7,"
            frontingTypeReality=07_VLESS_vision_reality_inbounds
            singBoxVLESSRealityVisionPort=$(jq -r .inbounds[0].listen_port "${row}.json")
            singBoxVLESSRealityVisionServerName=$(jq -r .inbounds[0].tls.server_name "${row}.json")
            realityDomainPort=$(jq -r .inbounds[0].tls.reality.handshake.server_port "${row}.json")

            realityServerName=${singBoxVLESSRealityVisionServerName}
            if [[ -f "${configPath}reality_key" ]]; then
                singBoxVLESSRealityPublicKey=$(grep "publicKey" <"${configPath}reality_key" | awk -F "[:]" '{print $2}')
                currentRealityPrivateKey=$(jq -r .inbounds[0].tls.reality.private_key "${row}.json")
                currentRealityPublicKey=$(grep "publicKey" <"${configPath}reality_key" | awk -F "[:]" '{print $2}')
            fi
        fi
        if echo "${row}" | grep -q VLESS_vision_gRPC_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}8,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingTypeReality=08_VLESS_vision_gRPC_inbounds
                singBoxVLESSRealityGRPCPort=$(jq -r .inbounds[0].listen_port "${row}.json")
                singBoxVLESSRealityGRPCServerName=$(jq -r .inbounds[0].tls.server_name "${row}.json")
                if [[ -f "${configPath}reality_key" ]]; then
                    singBoxVLESSRealityPublicKey=$(grep "publicKey" <"${configPath}reality_key" | awk -F "[:]" '{print $2}')
                fi
            fi
        fi
        if echo "${row}" | grep -q tuic_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}9,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=09_tuic_inbounds
                singBoxTuicPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q naive_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}10,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=10_naive_inbounds
                singBoxNaivePort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q anytls_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}13,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=13_anytls_inbounds
                singBoxAnyTLSPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VMess_HTTPUpgrade_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}11,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=11_VMess_HTTPUpgrade_inbounds
                singBoxVMessHTTPUpgradePort=$(grep 'listen' <${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf | awk '{print $2}')
            fi
        fi
        if echo "${row}" | grep -q socks5_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}20,"
            singBoxSocks5Port=$(jq .inbounds[0].listen_port "${row}.json")
        fi

    done < <(find ${configPath} -name "*inbounds.json" | sort | awk -F "[.]" '{print $1}')

    if [[ "${currentInstallProtocolType:0:1}" != "," ]]; then
        currentInstallProtocolType=",${currentInstallProtocolType}"
    fi
}

# 检查是否安装宝塔
checkBTPanel() {
    if [[ -n $(pgrep -f "BT-Panel") ]]; then
        # 读取域名
        if [[ -d '/www/server/panel/vhost/cert/' && -n $(find /www/server/panel/vhost/cert/*/fullchain.pem) ]]; then
            if [[ -z "${currentHost}" ]]; then
                echoContent skyBlue "\n读取宝塔配置\n"

                find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}'

                read -r -p "请输入编号选择:" selectBTDomain
            else
                selectBTDomain=$(find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}' | grep "${currentHost}" | cut -d ":" -f 1)
            fi

            if [[ -n "${selectBTDomain}" ]]; then
                btDomain=$(find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}' | grep -e "^${selectBTDomain}:" | cut -d ":" -f 2)

                if [[ -z "${btDomain}" ]]; then
                    echoContent red " ---> 选择错误，请重新选择"
                    checkBTPanel
                else
                    domain=${btDomain}
                    if [[ ! -f "/etc/v2ray-agent/tls/${btDomain}.crt" && ! -f "/etc/v2ray-agent/tls/${btDomain}.key" ]]; then
                        ln -s "/www/server/panel/vhost/cert/${btDomain}/fullchain.pem" "/etc/v2ray-agent/tls/${btDomain}.crt"
                        ln -s "/www/server/panel/vhost/cert/${btDomain}/privkey.pem" "/etc/v2ray-agent/tls/${btDomain}.key"
                    fi

                    nginxStaticPath="/www/wwwroot/${btDomain}/html/"

                    mkdir -p "/www/wwwroot/${btDomain}/html/"

                    if [[ -f "/www/wwwroot/${btDomain}/.user.ini" ]]; then
                        chattr -i "/www/wwwroot/${btDomain}/.user.ini"
                    fi
                    nginxConfigPath="/www/server/panel/vhost/nginx/"
                fi
            else
                echoContent red " ---> 选择错误，请重新选择"
                checkBTPanel
            fi
        fi
    fi
}
check1Panel() {
    if [[ -n $(pgrep -f "1panel") ]]; then
        # 读取域名
        if [[ -d '/opt/1panel/apps/openresty/openresty/www/sites/' && -n $(find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem) ]]; then
            if [[ -z "${currentHost}" ]]; then
                echoContent skyBlue "\n读取1Panel配置\n"

                find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem | awk -F "[/]" '{print $9}' | awk '{print NR""":"$0}'

                read -r -p "请输入编号选择:" selectBTDomain
            else
                selectBTDomain=$(find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem | awk -F "[/]" '{print $9}' | awk '{print NR""":"$0}' | grep "${currentHost}" | cut -d ":" -f 1)
            fi

            if [[ -n "${selectBTDomain}" ]]; then
                btDomain=$(find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem | awk -F "[/]" '{print $9}' | awk '{print NR""":"$0}' | grep "${selectBTDomain}:" | cut -d ":" -f 2)

                if [[ -z "${btDomain}" ]]; then
                    echoContent red " ---> 选择错误，请重新选择"
                    check1Panel
                else
                    domain=${btDomain}
                    if [[ ! -f "/etc/v2ray-agent/tls/${btDomain}.crt" && ! -f "/etc/v2ray-agent/tls/${btDomain}.key" ]]; then
                        ln -s "/opt/1panel/apps/openresty/openresty/www/sites/${btDomain}/ssl/fullchain.pem" "/etc/v2ray-agent/tls/${btDomain}.crt"
                        ln -s "/opt/1panel/apps/openresty/openresty/www/sites/${btDomain}/ssl/privkey.pem" "/etc/v2ray-agent/tls/${btDomain}.key"
                    fi

                    nginxStaticPath="/opt/1panel/apps/openresty/openresty/www/sites/${btDomain}/index/"
                fi
            else
                echoContent red " ---> 选择错误，请重新选择"
                check1Panel
            fi
        fi
    fi
}
# 读取当前alpn的顺序
readInstallAlpn() {
    if [[ -n "${currentInstallProtocolType}" && -z "${realityStatus}" ]]; then
        local alpn
        alpn=$(jq -r .inbounds[0].streamSettings.tlsSettings.alpn[0] ${configPath}${frontingType}.json)
        if [[ -n ${alpn} ]]; then
            currentAlpn=${alpn}
        fi
    fi
}

# 检查防火墙
allowPort() {
    local type=$2
    if [[ -z "${type}" ]]; then
        type=tcp
    fi
    # 如果防火墙启动状态则添加相应的开放端口
    if command -v dpkg >/dev/null 2>&1 && dpkg -l | grep -q "^[[:space:]]*ii[[:space:]]\+ufw"; then
        if ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "$1/${type}"; then
                sudo ufw allow "$1/${type}"
                checkUFWAllowPort "$1"
            fi
        fi
    elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
        local updateFirewalldStatus=
        if ! firewall-cmd --list-ports --permanent | grep -qw "$1/${type}"; then
            updateFirewalldStatus=true
            local firewallPort=$1
            if echo "${firewallPort}" | grep -q ":"; then
                firewallPort=$(echo "${firewallPort}" | awk -F ":" '{print $1"-"$2}')
            fi
            firewall-cmd --zone=public --add-port="${firewallPort}/${type}" --permanent
            checkFirewalldAllowPort "${firewallPort}"
        fi

        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            firewall-cmd --reload
        fi
    elif rc-update show 2>/dev/null | grep -q ufw; then
        if ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "$1/${type}"; then
                sudo ufw allow "$1/${type}"
                checkUFWAllowPort "$1"
            fi
        fi
    elif dpkg -l | grep -q "^[[:space:]]*ii[[:space:]]\+netfilter-persistent" && systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
        local updateFirewalldStatus=
        if ! iptables -L | grep -q "$1/${type}(mack-a)"; then
            updateFirewalldStatus=true
            iptables -I INPUT -p ${type} --dport "$1" -m comment --comment "allow $1/${type}(mack-a)" -j ACCEPT
        fi

        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            netfilter-persistent save
        fi
    fi
}
# 获取公网IP
getPublicIP() {
    local type=4
    if [[ -n "$1" ]]; then
        type=$1
    fi
    if [[ -n "${currentHost}" && -z "$1" ]] && [[ "${singBoxVLESSRealityVisionServerName}" == "${currentHost}" || "${singBoxVLESSRealityGRPCServerName}" == "${currentHost}" ]]; then
        echo "${currentHost}"
    else
        local currentIP=
        currentIP=$(curl -s "-${type}" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
        if [[ -z "${currentIP}" && -z "$1" ]]; then
            currentIP=$(curl -s "-6" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
        fi
        echo "${currentIP}"
    fi

}

# 输出ufw端口开放状态
checkUFWAllowPort() {
    if ufw status | grep -q "$1"; then
        echoContent green " ---> $1端口开放成功"
    else
        echoContent red " ---> $1端口开放失败"
        exit 0
    fi
}

# 输出firewall-cmd端口开放状态
checkFirewalldAllowPort() {
    if firewall-cmd --list-ports --permanent | grep -q "$1"; then
        echoContent green " ---> $1端口开放成功"
    else
        echoContent red " ---> $1端口开放失败"
        exit 0
    fi
}

# 读取Tuic配置
readSingBoxConfig() {
    tuicPort=
    hysteriaPort=
    if [[ -n "${singBoxConfigPath}" ]]; then

        if [[ -f "${singBoxConfigPath}09_tuic_inbounds.json" ]]; then
            tuicPort=$(jq -r '.inbounds[0].listen_port' "${singBoxConfigPath}09_tuic_inbounds.json")
            tuicAlgorithm=$(jq -r '.inbounds[0].congestion_control' "${singBoxConfigPath}09_tuic_inbounds.json")
        fi
        if [[ -f "${singBoxConfigPath}06_hysteria2_inbounds.json" ]]; then
            hysteriaPort=$(jq -r '.inbounds[0].listen_port' "${singBoxConfigPath}06_hysteria2_inbounds.json")
            hysteria2ClientUploadSpeed=$(jq -r '.inbounds[0].down_mbps' "${singBoxConfigPath}06_hysteria2_inbounds.json")
            hysteria2ClientDownloadSpeed=$(jq -r '.inbounds[0].up_mbps' "${singBoxConfigPath}06_hysteria2_inbounds.json")
        fi
    fi
}

# 读取上次安装的配置
readLastInstallationConfig() {
    if [[ -n "${configPath}" ]]; then
        read -r -p "读取到上次安装的配置，是否使用 ？[y/n]:" lastInstallationConfigStatus
        if [[ "${lastInstallationConfigStatus}" == "y" ]]; then
            lastInstallationConfig=true
        fi
    fi
}
# 卸载 sing-box
unInstallSingBox() {
    local type=$1
    if [[ -n "${singBoxConfigPath}" ]]; then
        if grep -q 'tuic' </etc/v2ray-agent/sing-box/conf/config.json && [[ "${type}" == "tuic" ]]; then
            rm "${singBoxConfigPath}09_tuic_inbounds.json"
            echoContent green " ---> 删除sing-box tuic配置成功"
        fi

        if grep -q 'hysteria2' </etc/v2ray-agent/sing-box/conf/config.json && [[ "${type}" == "hysteria2" ]]; then
            rm "${singBoxConfigPath}06_hysteria2_inbounds.json"
            echoContent green " ---> 删除sing-box hysteria2配置成功"
        fi
        rm "${singBoxConfigPath}config.json"
    fi

    readInstallType

    if [[ -n "${singBoxConfigPath}" ]]; then
        echoContent yellow " ---> 检测到有其他配置，保留sing-box核心"
        handleSingBox stop
        handleSingBox start
    else
        handleSingBox stop
        rm /etc/systemd/system/sing-box.service
        rm -rf /etc/v2ray-agent/sing-box/*
        echoContent green " ---> sing-box 卸载完成"
    fi
}

# 检查文件目录以及path路径
readConfigHostPathUUID() {
    currentPath=
    currentDefaultPort=
    currentUUID=
    currentClients=
    currentHost=
    currentPort=
    currentCDNAddress=
    singBoxVMessWSPath=
    singBoxVLESSWSPath=
    singBoxVMessHTTPUpgradePath=

    if [[ "${coreInstallType}" == "2" ]]; then
        if [[ -n "${frontingType}" ]]; then
            currentHost=$(jq -r .inbounds[0].tls.server_name ${configPath}${frontingType}.json)
            if echo ${currentInstallProtocolType} | grep -q ",11," && [[ "${currentHost}" == "null" ]]; then
                currentHost=$(grep 'server_name' <${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf | awk '{print $2}')
                currentHost=${currentHost//;/}
            fi
            currentUUID=$(jq -r .inbounds[0].users[0].uuid ${configPath}${frontingType}.json)
            currentClients=$(jq -r .inbounds[0].users ${configPath}${frontingType}.json)
        else
            currentUUID=$(jq -r .inbounds[0].users[0].uuid ${configPath}${frontingTypeReality}.json)
            currentClients=$(jq -r .inbounds[0].users ${configPath}${frontingTypeReality}.json)
        fi
    fi

    # 读取path
    if [[ -n "${configPath}" && -n "${frontingType}" ]]; then
        if [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}05_VMess_WS_inbounds.json" ]]; then
            singBoxVMessWSPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}05_VMess_WS_inbounds.json")
            currentPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}05_VMess_WS_inbounds.json" | awk -F "[/]" '{print $2}')
        fi
        if [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}03_VLESS_WS_inbounds.json" ]]; then
            singBoxVLESSWSPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}03_VLESS_WS_inbounds.json")
            currentPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}03_VLESS_WS_inbounds.json" | awk -F "[/]" '{print $2}')
            currentPath=${currentPath::-2}
        fi
        if [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json" ]]; then
            singBoxVMessHTTPUpgradePath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json")
            currentPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json" | awk -F "[/]" '{print $2}')
            # currentPath=${currentPath::-2}
        fi
    fi
    if [[ -f "/etc/v2ray-agent/cdn" ]] && [[ -n "$(head -1 /etc/v2ray-agent/cdn)" ]]; then
        currentCDNAddress=$(head -1 /etc/v2ray-agent/cdn)
    else
        currentCDNAddress="${currentHost}"
    fi
}

# 状态展示
showInstallStatus() {
    if [[ -n "${coreInstallType}" ]]; then
        if [[ -n $(pgrep -f "sing-box/sing-box") ]]; then
            echoContent yellow "\n核心: sing-box[运行中]"
        else
            echoContent yellow "\n核心: sing-box[未运行]"
        fi
        # 读取协议类型
        readInstallProtocolType

        if [[ -n ${currentInstallProtocolType} ]]; then
            echoContent yellow "已安装协议: \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",0,"; then
            echoContent yellow "VLESS+TCP[TLS_Vision] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",1,"; then
            echoContent yellow "VLESS+WS[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",2,"; then
            echoContent yellow "Trojan+gRPC[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",3,"; then
            echoContent yellow "VMess+WS[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",4,"; then
            echoContent yellow "Trojan+TCP[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",5,"; then
            echoContent yellow "VLESS+gRPC[TLS] \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",6,"; then
            echoContent yellow "Hysteria2 \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",7,"; then
            echoContent yellow "VLESS+Reality+Vision \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",8,"; then
            echoContent yellow "VLESS+Reality+gRPC \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",9,"; then
            echoContent yellow "Tuic \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",10,"; then
            echoContent yellow "Naive \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",11,"; then
            echoContent yellow "VMess+TLS+HTTPUpgrade \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",12,"; then
            echoContent yellow "VLESS+Reality+XHTTP \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",13,"; then
            echoContent yellow "AnyTLS \c"
        fi
    fi
}

# 清理旧残留
cleanUp() {
    if [[ "$1" == "singBoxDel" ]]; then
        handleSingBox stop
        rm -rf /etc/v2ray-agent/sing-box/conf/config.json >/dev/null 2>&1
        rm -rf /etc/v2ray-agent/sing-box/conf/config/* >/dev/null 2>&1
    fi
}
initVar "$1"
checkSystem
checkCPUVendor

readInstallType
readInstallProtocolType
readConfigHostPathUUID
readCustomPort
readSingBoxConfig
# -------------------------------------------------------------

# 初始化安装目录
mkdirTools() {
    mkdir -p /etc/v2ray-agent/tls
    mkdir -p /etc/v2ray-agent/subscribe_local/default
    mkdir -p /etc/v2ray-agent/subscribe_local/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe_remote/default
    mkdir -p /etc/v2ray-agent/subscribe_remote/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe/default
    mkdir -p /etc/v2ray-agent/subscribe/clashMetaProfiles
    mkdir -p /etc/v2ray-agent/subscribe/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe/sing-box
    mkdir -p /etc/v2ray-agent/subscribe/sing-box_profiles
    mkdir -p /etc/v2ray-agent/subscribe_local/sing-box

    mkdir -p /etc/systemd/system/
    mkdir -p /tmp/v2ray-agent-tls/

    mkdir -p /etc/v2ray-agent/warp

    mkdir -p /etc/v2ray-agent/sing-box/conf/config

    mkdir -p /usr/share/nginx/html/
}
# 检测root
checkRoot() {
    if [ "$(id -u)" -ne 0 ]; then
        #        sudoCMD="sudo"
        echo "检测到非 Root 用户，将使用 sudo 执行命令..."
    fi
}
# 安装工具包
installTools() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 安装工具"
    # 修复ubuntu个别系统问题
    if [[ "${release}" == "ubuntu" ]]; then
        dpkg --configure -a
    fi

    if [[ -n $(pgrep -f "apt") ]]; then
        pgrep -f apt | xargs kill -9
    fi

    echoContent green " ---> 检查、安装更新【新机器会很慢，如长时间无反应，请手动停止后重新执行】"

    if [[ "${release}" != "centos" ]]; then
        ${upgrade} >/etc/v2ray-agent/install.log 2>&1
    fi

    if grep <"/etc/v2ray-agent/install.log" -q "changed"; then
        ${updateReleaseInfoChange} >/dev/null 2>&1
    fi

    if [[ "${release}" == "centos" ]]; then
        rm -rf /var/run/yum.pid
        ${installType} epel-release >/dev/null 2>&1
    fi

    if ! sudo --version >/dev/null 2>&1; then
        echoContent green " ---> 安装sudo"
        ${installType} sudo >/dev/null 2>&1
    fi

    if ! wget --help >/dev/null 2>&1; then
        echoContent green " ---> 安装wget"
        ${installType} wget >/dev/null 2>&1
    fi

    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        if [[ "${release}" != "centos" ]]; then
            echoContent green " ---> 安装iptables"
            echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | sudo debconf-set-selections
            echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | sudo debconf-set-selections
            ${installType} iptables-persistent >/dev/null 2>&1
        fi
    fi

    if ! curl --help >/dev/null 2>&1; then
        echoContent green " ---> 安装curl"
        ${installType} curl >/dev/null 2>&1
    fi

    if ! unzip >/dev/null 2>&1; then
        echoContent green " ---> 安装unzip"
        ${installType} unzip >/dev/null 2>&1
    fi

    if ! socat -h >/dev/null 2>&1; then
        echoContent green " ---> 安装socat"
        ${installType} socat >/dev/null 2>&1
    fi

    if ! tar --help >/dev/null 2>&1; then
        echoContent green " ---> 安装tar"
        ${installType} tar >/dev/null 2>&1
    fi

    if ! crontab -l >/dev/null 2>&1; then
        echoContent green " ---> 安装crontabs"
        if [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
            ${installType} cron >/dev/null 2>&1
        else
            ${installType} crontabs >/dev/null 2>&1
        fi
    fi
    if ! jq --help >/dev/null 2>&1; then
        echoContent green " ---> 安装jq"
        ${installType} jq >/dev/null 2>&1
    fi

    if ! command -v ld >/dev/null 2>&1; then
        echoContent green " ---> 安装binutils"
        ${installType} binutils >/dev/null 2>&1
    fi

    if ! openssl help >/dev/null 2>&1; then
        echoContent green " ---> 安装openssl"
        ${installType} openssl >/dev/null 2>&1
    fi

    if ! ping6 --help >/dev/null 2>&1; then
        echoContent green " ---> 安装ping6"
        ${installType} inetutils-ping >/dev/null 2>&1
    fi

    if ! qrencode --help >/dev/null 2>&1; then
        echoContent green " ---> 安装qrencode"
        ${installType} qrencode >/dev/null 2>&1
    fi

    if ! command -v lsb_release >/dev/null 2>&1; then
        if [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
            ${installType} lsb-release >/dev/null 2>&1
        elif [[ "${release}" == "centos" ]]; then
            ${installType} redhat-lsb-core >/dev/null 2>&1
        else
            ${installType} lsb-release >/dev/null 2>&1
        fi
    fi

    if ! lsof -h >/dev/null 2>&1; then
        echoContent green " ---> 安装lsof"
        ${installType} lsof >/dev/null 2>&1
    fi

    if ! dig -h >/dev/null 2>&1; then
        echoContent green " ---> 安装dig"
        if echo "${installType}" | grep -qw "apt"; then
            ${installType} dnsutils >/dev/null 2>&1
        elif echo "${installType}" | grep -qw "yum"; then
            ${installType} bind-utils >/dev/null 2>&1
        elif echo "${installType}" | grep -qw "apk"; then
            ${installType} bind-tools >/dev/null 2>&1
        fi
    fi

    # 检测nginx版本，并提供是否卸载的选项
    if echo "${selectCustomInstallType}" | grep -qwE ",7,|,8,|,7,8,"; then
        echoContent green " ---> 检测到无需依赖Nginx的服务，跳过安装"
    else
        if ! nginx >/dev/null 2>&1; then
            echoContent green " ---> 安装nginx"
            installNginxTools
        else
            nginxVersion=$(nginx -v 2>&1)
            nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
            if [[ ${nginxVersion} -lt 14 ]]; then
                read -r -p "读取到当前的Nginx版本不支持gRPC，会导致安装失败，是否卸载Nginx后重新安装 ？[y/n]:" unInstallNginxStatus
                if [[ "${unInstallNginxStatus}" == "y" ]]; then
                    ${removeType} nginx >/dev/null 2>&1
                    echoContent yellow " ---> nginx卸载完成"
                    echoContent green " ---> 安装nginx"
                    installNginxTools >/dev/null 2>&1
                else
                    exit 0
                fi
            fi
        fi
    fi

    #    if ! command -v semanage >/dev/null 2>&1 && [[ "${release}" == "centos" ]]; then
    #        if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" == "Enforcing" ]; then
    #            if [[ "${centosVersion}" == "7" ]]; then
    #                policyCoreUtils="policycoreutils-python"
    #            elif [[ "${centosVersion}" == "8" || "${centosVersion}" == "9" || "${centosVersion}" == "10" ]]; then
    #                policyCoreUtils="policycoreutils-python-utils"
    #            fi
    #            echoContent green " ---> 安装semanage"
    #
    #            if [[ -n "${policyCoreUtils}" ]]; then
    #                ${installType} bash-completion >/dev/null 2>&1
    #                ${installType} ${policyCoreUtils} >/dev/null 2>&1
    #            fi
    #            if [[ -n $(which semanage) ]]; then
    #                semanage port -a -t http_port_t -p tcp 31300
    #            fi
    #        fi
    #    fi

    if [[ "${selectCustomInstallType}" == "7" ]]; then
        echoContent green " ---> 检测到无需依赖证书的服务，跳过安装"
    else
        if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
            echoContent green " ---> 安装acme.sh"
            curl -s https://get.acme.sh | sh >/etc/v2ray-agent/tls/acme.log 2>&1

            if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
                echoContent red "  acme安装失败--->"
                tail -n 100 /etc/v2ray-agent/tls/acme.log
                echoContent yellow "错误排查:"
                echoContent red "  1.获取Github文件失败，请等待Github恢复后尝试，恢复进度可查看 [https://www.githubstatus.com/]"
                echoContent red "  2.acme.sh脚本出现bug，可查看[https://github.com/acmesh-official/acme.sh] issues"
                echoContent red "  3.如纯IPv6机器，请设置NAT64,可执行下方命令，如果添加下方命令还是不可用，请尝试更换其他NAT64"
                echoContent skyBlue "  sed -i \"1i\\\nameserver 2a00:1098:2b::1\\\nnameserver 2a00:1098:2c::1\\\nnameserver 2a01:4f8:c2c:123f::1\\\nnameserver 2a01:4f9:c010:3f02::1\" /etc/resolv.conf"
                exit 0
            fi
        fi
    fi

}
# 开机启动
bootStartup() {
    local serviceName=$1
    if [[ "${release}" == "alpine" ]]; then
        rc-update add "${serviceName}" default
    else
        systemctl daemon-reload
        systemctl enable "${serviceName}"
    fi
}
# 安装Nginx
installNginxTools() {

    if [[ "${release}" == "debian" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        # gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        # gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "centos" ]]; then
        ${installType} yum-utils >/dev/null 2>&1
        cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
    elif [[ "${release}" == "alpine" ]]; then
        rm "${nginxConfigPath}default.conf"
    fi
    ${installType} nginx >/dev/null 2>&1
    bootStartup nginx
}

# 安装warp
installWarp() {
    if [[ "${cpuVendor}" == "arm" ]]; then
        echoContent red " ---> 官方WARP客户端不支持ARM架构"
        exit 0
    fi

    ${installType} gnupg2 -y >/dev/null 2>&1
    if [[ "${release}" == "debian" ]]; then
        curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
        echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
        echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "centos" ]]; then
        ${installType} yum-utils >/dev/null 2>&1
        sudo rpm -ivh "http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm" >/dev/null 2>&1
    fi

    echoContent green " ---> 安装WARP"
    ${installType} cloudflare-warp >/dev/null 2>&1
    if [[ -z $(which warp-cli) ]]; then
        echoContent red " ---> 安装WARP失败"
        exit 0
    fi
    systemctl enable warp-svc
    warp-cli --accept-tos register
    warp-cli --accept-tos set-mode proxy
    warp-cli --accept-tos set-proxy-port 31303
    warp-cli --accept-tos connect
    warp-cli --accept-tos enable-always-on

    local warpStatus=
    warpStatus=$(curl -s --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace | grep "warp" | cut -d "=" -f 2)

    if [[ "${warpStatus}" == "on" ]]; then
        echoContent green " ---> WARP启动成功"
    fi
}

# 通过dns检查域名的IP
checkDNSIP() {
    local domain=$1
    local dnsIP=
    ipType=4
    dnsIP=$(dig @1.1.1.1 +time=2 +short "${domain}" | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    if [[ -z "${dnsIP}" ]]; then
        dnsIP=$(dig @8.8.8.8 +time=2 +short "${domain}" | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    fi
    if echo "${dnsIP}" | grep -q "timed out" || [[ -z "${dnsIP}" ]]; then
        echo
        echoContent red " ---> 无法通过DNS获取域名 IPv4 地址"
        echoContent green " ---> 尝试检查域名 IPv6 地址"
        dnsIP=$(dig @2606:4700:4700::1111 +time=2 aaaa +short "${domain}")
        ipType=6
        if echo "${dnsIP}" | grep -q "network unreachable" || [[ -z "${dnsIP}" ]]; then
            echoContent red " ---> 无法通过DNS获取域名IPv6地址，退出安装"
            exit 0
        fi
    fi
    local publicIP=

    publicIP=$(getPublicIP "${ipType}")
    if [[ "${publicIP}" != "${dnsIP}" ]]; then
        echoContent red " ---> 域名解析IP与当前服务器IP不一致\n"
        echoContent yellow " ---> 请检查域名解析是否生效以及正确"
        echoContent green " ---> 当前VPS IP：${publicIP}"
        echoContent green " ---> DNS解析 IP：${dnsIP}"
        exit 0
    else
        echoContent green " ---> 域名IP校验通过"
    fi
}
# 检查端口实际开放状态
checkPortOpen() {
    handleSingBox stop >/dev/null 2>&1

    local port=$1
    local domain=$2
    local checkPortOpenResult=
    allowPort "${port}"

    if [[ -z "${btDomain}" ]]; then

        handleNginx stop
        # 初始化nginx配置
        touch ${nginxConfigPath}checkPortOpen.conf
        local listenIPv6PortConfig=

        if [[ -n $(curl -s -6 -m 4 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2) ]]; then
            listenIPv6PortConfig="listen [::]:${port};"
        fi
        cat <<EOF >${nginxConfigPath}checkPortOpen.conf
server {
    listen ${port};
    ${listenIPv6PortConfig}
    server_name ${domain};
    location /checkPort {
        return 200 'fjkvymb6len';
    }
    location /ip {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header REMOTE-HOST \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        default_type text/plain;
        return 200 \$proxy_add_x_forwarded_for;
    }
}
EOF
        handleNginx start
        # 检查域名+端口的开放
        checkPortOpenResult=$(curl -s -m 10 "http://${domain}:${port}/checkPort")
        localIP=$(curl -s -m 10 "http://${domain}:${port}/ip")
        rm "${nginxConfigPath}checkPortOpen.conf"
        handleNginx stop
        if [[ "${checkPortOpenResult}" == "fjkvymb6len" ]]; then
            echoContent green " ---> 检测到${port}端口已开放"
        else
            echoContent green " ---> 未检测到${port}端口开放，退出安装"
            if echo "${checkPortOpenResult}" | grep -q "cloudflare"; then
                echoContent yellow " ---> 请关闭云朵后等待三分钟重新尝试"
            else
                if [[ -z "${checkPortOpenResult}" ]]; then
                    echoContent red " ---> 请检查是否有网页防火墙，比如Oracle等云服务商"
                    echoContent red " ---> 检查是否自己安装过nginx并且有配置冲突，可以尝试DD纯净系统后重新尝试"
                else
                    echoContent red " ---> 错误日志：${checkPortOpenResult}，请将此错误日志通过issues提交反馈"
                fi
            fi
            exit 0
        fi
        checkIP "${localIP}"
    fi
}

# 初始化Nginx申请证书配置
initTLSNginxConfig() {
    handleNginx stop
    echoContent skyBlue "\n进度  $1/${totalProgress} : 初始化Nginx申请证书配置"
    if [[ -n "${currentHost}" && -z "${lastInstallationConfig}" ]]; then
        echo
        read -r -p "读取到上次安装记录，是否使用上次安装时的域名 ？[y/n]:" historyDomainStatus
        if [[ "${historyDomainStatus}" == "y" ]]; then
            domain=${currentHost}
            echoContent yellow "\n ---> 域名: ${domain}"
        else
            echo
            echoContent yellow "请输入要配置的域名 例: www.v2ray-agent.com --->"
            read -r -p "域名:" domain
        fi
    elif [[ -n "${currentHost}" && -n "${lastInstallationConfig}" ]]; then
        domain=${currentHost}
    else
        echo
        echoContent yellow "请输入要配置的域名 例: www.v2ray-agent.com --->"
        read -r -p "域名:" domain
    fi

    if [[ -z ${domain} ]]; then
        echoContent red "  域名不可为空--->"
        initTLSNginxConfig 3
    else
        dnsTLSDomain=$(echo "${domain}" | awk -F "." '{$1="";print $0}' | sed 's/^[[:space:]]*//' | sed 's/ /./g')
        # 修改配置
        handleNginx stop
    fi
}

# 删除nginx默认的配置
removeNginxDefaultConf() {
    if [[ -f ${nginxConfigPath}default.conf ]]; then
        if [[ "$(grep -c "server_name" <${nginxConfigPath}default.conf)" == "1" ]] && [[ "$(grep -c "server_name  localhost;" <${nginxConfigPath}default.conf)" == "1" ]]; then
            echoContent green " ---> 删除Nginx默认配置"
            rm -rf ${nginxConfigPath}default.conf >/dev/null 2>&1
        fi
    fi
}
# 修改nginx重定向配置
updateRedirectNginxConf() {
    local redirectDomain=
    redirectDomain=${domain}:${port}

    local nginxH2Conf=
    nginxH2Conf="listen 127.0.0.1:31302 http2 so_keepalive=on proxy_protocol;"
    nginxVersion=$(nginx -v 2>&1)

    if echo "${nginxVersion}" | grep -q "1.25" && [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $3}') -gt 0 ]] || [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $2}') -gt 25 ]]; then
        nginxH2Conf="listen 127.0.0.1:31302 so_keepalive=on proxy_protocol;http2 on;"
    fi

    cat <<EOF >${nginxConfigPath}alone.conf
    server {
    		listen 127.0.0.1:31300;
    		server_name _;
    		return 403;
    }
EOF

    if echo "${selectCustomInstallType}" | grep -qE ",2,|,5," || [[ -z "${selectCustomInstallType}" ]]; then

        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}
	server_name ${domain};
	root ${nginxStaticPath};

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

	client_header_timeout 1071906480m;
    keepalive_timeout 1071906480m;

    location /${currentPath}grpc {
    	if (\$content_type !~ "application/grpc") {
    		return 404;
    	}
 		client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		if (\$content_type !~ "application/grpc") {
            		return 404;
		}
 		client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
	location / {
    }
}
EOF
    elif echo "${selectCustomInstallType}" | grep -q ",5," || [[ -z "${selectCustomInstallType}" ]]; then
        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}

	set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

	server_name ${domain};
	root ${nginxStaticPath};

	location /${currentPath}grpc {
		client_max_body_size 0;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
	location / {
    }
}
EOF

    elif echo "${selectCustomInstallType}" | grep -q ",2," || [[ -z "${selectCustomInstallType}" ]]; then
        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}

	set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    server_name ${domain};
	root ${nginxStaticPath};

	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
	location / {
    }
}
EOF
    else

        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}

	set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

	server_name ${domain};
	root ${nginxStaticPath};

	location / {
	}
}
EOF
    fi

    cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31300 proxy_protocol;
	server_name ${domain};

	set_real_ip_from 127.0.0.1;
	real_ip_header proxy_protocol;

	root ${nginxStaticPath};
	location / {
	}
}
EOF
    handleNginx stop
}
# singbox Nginx config
singBoxNginxConfig() {
    local type=$1
    local port=$2

    local nginxH2Conf=
    nginxH2Conf="listen ${port} http2 so_keepalive=on ssl;"
    nginxVersion=$(nginx -v 2>&1)

    local singBoxNginxSSL=
    singBoxNginxSSL="ssl_certificate /etc/v2ray-agent/tls/${domain}.crt;ssl_certificate_key /etc/v2ray-agent/tls/${domain}.key;"

    if echo "${nginxVersion}" | grep -q "1.25" && [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $3}') -gt 0 ]] || [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $2}') -gt 25 ]]; then
        nginxH2Conf="listen ${port} so_keepalive=on ssl;http2 on;"
    fi

    if echo "${selectCustomInstallType}" | grep -q ",11," || [[ "$1" == "all" ]]; then
        cat <<EOF >>${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf
server {
	${nginxH2Conf}

	server_name ${domain};
	root ${nginxStaticPath};
    ${singBoxNginxSSL}

    ssl_protocols              TLSv1.2 TLSv1.3;
    ssl_ciphers                TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers  on;

    resolver                   1.1.1.1 valid=60s;
    resolver_timeout           2s;
    client_max_body_size 100m;

    location /${currentPath} {
    	if (\$http_upgrade != "websocket") {
            return 444;
        }

        proxy_pass                          http://127.0.0.1:31306;
        proxy_http_version                  1.1;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         "upgrade";
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header Host               \$host;
        proxy_redirect                      off;
	}
}
EOF
    fi
}

# 检查ip
checkIP() {
    echoContent skyBlue "\n ---> 检查域名ip中"
    local localIP=$1

    if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
        echoContent red "\n ---> 未检测到当前域名的ip"
        echoContent skyBlue " ---> 请依次进行下列检查"
        echoContent yellow " --->  1.检查域名是否书写正确"
        echoContent yellow " --->  2.检查域名dns解析是否正确"
        echoContent yellow " --->  3.如解析正确，请等待dns生效，预计三分钟内生效"
        echoContent yellow " --->  4.如报Nginx启动问题，请手动启动nginx查看错误，如自己无法处理请提issues"
        echo
        echoContent skyBlue " ---> 如以上设置都正确，请重新安装纯净系统后再次尝试"

        if [[ -n ${localIP} ]]; then
            echoContent yellow " ---> 检测返回值异常，建议手动卸载nginx后重新执行脚本"
            echoContent red " ---> 异常结果：${localIP}"
        fi
        exit 0
    else
        if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q ":"; then
            echoContent red "\n ---> 检测到多个ip，请确认是否关闭cloudflare的云朵"
            echoContent yellow " ---> 关闭云朵后等待三分钟后重试"
            echoContent yellow " ---> 检测到的ip如下:[${localIP}]"
            exit 0
        fi
        echoContent green " ---> 检查当前域名IP正确"
    fi
}
# 自定义email
customSSLEmail() {
    if echo "$1" | grep -q "validate email"; then
        read -r -p "是否重新输入邮箱地址[y/n]:" sslEmailStatus
        if [[ "${sslEmailStatus}" == "y" ]]; then
            sed '/ACCOUNT_EMAIL/d' /root/.acme.sh/account.conf >/root/.acme.sh/account.conf_tmp && mv /root/.acme.sh/account.conf_tmp /root/.acme.sh/account.conf
        else
            exit 0
        fi
    fi

    if [[ -d "/root/.acme.sh" && -f "/root/.acme.sh/account.conf" ]]; then
        if ! grep -q "ACCOUNT_EMAIL" <"/root/.acme.sh/account.conf" && ! echo "${sslType}" | grep -q "letsencrypt"; then
            read -r -p "请输入邮箱地址:" sslEmail
            if echo "${sslEmail}" | grep -q "@"; then
                echo "ACCOUNT_EMAIL='${sslEmail}'" >>/root/.acme.sh/account.conf
                echoContent green " ---> 添加完毕"
            else
                echoContent yellow "请重新输入正确的邮箱格式[例: username@example.com]"
                customSSLEmail
            fi
        fi
    fi

}
# DNS API申请证书
switchDNSAPI() {
    read -r -p "是否使用DNS API申请证书[支持NAT]？[y/n]:" dnsAPIStatus
    if [[ "${dnsAPIStatus}" == "y" ]]; then
        echoContent red "\n=============================================================="
        echoContent yellow "1.cloudflare[默认]"
        echoContent yellow "2.aliyun"
        echoContent red "=============================================================="
        read -r -p "请选择[回车]使用默认:" selectDNSAPIType
        case ${selectDNSAPIType} in
        1)
            dnsAPIType="cloudflare"
            ;;
        2)
            dnsAPIType="aliyun"
            ;;
        *)
            dnsAPIType="cloudflare"
            ;;
        esac
        initDNSAPIConfig "${dnsAPIType}"
    fi
}
# 初始化dns配置
initDNSAPIConfig() {
    if [[ "$1" == "cloudflare" ]]; then
        echoContent yellow "\n CF_Token参考配置教程：https://www.v2ray-agent.com/archives/1701160377972\n"
        read -r -p "请输入API Token:" cfAPIToken
        if [[ -z "${cfAPIToken}" ]]; then
            echoContent red " ---> 输入为空，请重新输入"
            initDNSAPIConfig "$1"
        else
            echo
            if ! echo "${dnsTLSDomain}" | grep -q "\." || [[ -z $(echo "${dnsTLSDomain}" | awk -F "[.]" '{print $1}') ]]; then
                echoContent green " ---> 不支持此域名申请通配符证书，建议使用此格式[xx.xx.xx]"
                exit 0
            fi
            read -r -p "是否使用*.${dnsTLSDomain}进行API申请通配符证书？[y/n]:" dnsAPIStatus
        fi
    elif [[ "$1" == "aliyun" ]]; then
        read -r -p "请输入Ali Key:" aliKey
        read -r -p "请输入Ali Secret:" aliSecret
        if [[ -z "${aliKey}" || -z "${aliSecret}" ]]; then
            echoContent red " ---> 输入为空，请重新输入"
            initDNSAPIConfig "$1"
        else
            echo
            if ! echo "${dnsTLSDomain}" | grep -q "\." || [[ -z $(echo "${dnsTLSDomain}" | awk -F "[.]" '{print $1}') ]]; then
                echoContent green " ---> 不支持此域名申请通配符证书，建议使用此格式[xx.xx.xx]"
                exit 0
            fi
            read -r -p "是否使用*.${dnsTLSDomain}进行API申请通配符证书？[y/n]:" dnsAPIStatus
        fi
    fi
}
# 选择ssl安装类型
switchSSLType() {
    if [[ -z "${sslType}" ]]; then
        echoContent red "\n=============================================================="
        echoContent yellow "1.letsencrypt[默认]"
        echoContent yellow "2.zerossl"
        echoContent yellow "3.buypass[不支持DNS申请]"
        echoContent red "=============================================================="
        read -r -p "请选择[回车]使用默认:" selectSSLType
        case ${selectSSLType} in
        1)
            sslType="letsencrypt"
            ;;
        2)
            sslType="zerossl"
            ;;
        3)
            sslType="buypass"
            ;;
        *)
            sslType="letsencrypt"
            ;;
        esac
        if [[ -n "${dnsAPIType}" && "${sslType}" == "buypass" ]]; then
            echoContent red " ---> buypass不支持API申请证书"
            exit 0
        fi
        echo "${sslType}" >/etc/v2ray-agent/tls/ssl_type
    fi
}

# 选择acme安装证书方式
selectAcmeInstallSSL() {
    #    local sslIPv6=
    #    local currentIPType=
    if [[ "${ipType}" == "6" ]]; then
        sslIPv6="--listen-v6"
    fi
    #    currentIPType=$(curl -s "-${ipType}" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)

    #    if [[ -z "${currentIPType}" ]]; then
    #                currentIPType=$(curl -s -6 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)
    #        if [[ -n "${currentIPType}" ]]; then
    #            sslIPv6="--listen-v6"
    #        fi
    #    fi

    acmeInstallSSL

    readAcmeTLS
}

# 安装SSL证书
acmeInstallSSL() {
    local dnsAPIDomain="${tlsDomain}"
    if [[ "${dnsAPIStatus}" == "y" ]]; then
        dnsAPIDomain="*.${dnsTLSDomain}"
    fi

    if [[ "${dnsAPIType}" == "cloudflare" ]]; then
        echoContent green " ---> DNS API 生成证书中"
        sudo CF_Token="${cfAPIToken}" "$HOME/.acme.sh/acme.sh" --issue -d "${dnsAPIDomain}" -d "${dnsTLSDomain}" --dns dns_cf -k ec-256 --server "${sslType}" ${sslIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
    elif [[ "${dnsAPIType}" == "aliyun" ]]; then
        echoContent green " --->  DNS API 生成证书中"
        sudo Ali_Key="${aliKey}" Ali_Secret="${aliSecret}" "$HOME/.acme.sh/acme.sh" --issue -d "${dnsAPIDomain}" -d "${dnsTLSDomain}" --dns dns_ali -k ec-256 --server "${sslType}" ${sslIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
    else
        echoContent green " ---> 生成证书中"
        sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server "${sslType}" ${sslIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
    fi
}
# 自定义端口
customPortFunction() {
    local historyCustomPortStatus=
    if [[ -n "${customPort}" || -n "${currentPort}" ]]; then
        echo
        if [[ -z "${lastInstallationConfig}" ]]; then
            read -r -p "读取到上次安装时的端口，是否使用上次安装时的端口？[y/n]:" historyCustomPortStatus
            if [[ "${historyCustomPortStatus}" == "y" ]]; then
                port=${currentPort}
                echoContent yellow "\n ---> 端口: ${port}"
            fi
        elif [[ -n "${lastInstallationConfig}" ]]; then
            port=${currentPort}
        fi
    fi
    if [[ -z "${currentPort}" ]] || [[ "${historyCustomPortStatus}" == "n" ]]; then
        echo

        if [[ -n "${btDomain}" ]]; then
            echoContent yellow "请输入端口[不可与BT Panel/1Panel端口相同，回车随机]"
            read -r -p "端口:" port
            if [[ -z "${port}" ]]; then
                port=$((RANDOM % 20001 + 10000))
            fi
        else
            echo
            echoContent yellow "请输入端口[默认: 443]，可自定义端口[回车使用默认]"
            read -r -p "端口:" port
            if [[ -z "${port}" ]]; then
                port=443
            fi
        fi

        if [[ -n "${port}" ]]; then
            if ((port >= 1 && port <= 65535)); then
                allowPort "${port}"
                echoContent yellow "\n ---> 端口: ${port}"
                if [[ -z "${btDomain}" ]]; then
                    checkDNSIP "${domain}"
                    removeNginxDefaultConf
                    checkPortOpen "${port}" "${domain}"
                fi
            else
                echoContent red " ---> 端口输入错误"
                exit 0
            fi
        else
            echoContent red " ---> 端口不可为空"
            exit 0
        fi
    fi
}

# 检测端口是否占用
checkPort() {
    if [[ -n "$1" ]] && lsof -i "tcp:$1" | grep -q LISTEN; then
        echoContent red "\n ---> $1端口被占用，请手动关闭后安装\n"
        lsof -i "tcp:$1" | grep LISTEN
        exit 0
    fi
}

# 安装TLS
installTLS() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 申请TLS证书\n"
    readAcmeTLS
    local tlsDomain=${domain}

    # 安装tls
    if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
        echoContent green " ---> 检测到证书"
        renewalTLS

        if [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
            if [[ "${installedDNSAPIStatus}" == "true" ]]; then
                sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
            else
                sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
            fi

        else
            if [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
                if [[ -z "${lastInstallationConfig}" ]]; then
                    echoContent yellow " ---> 如未过期或者自定义证书请选择[n]\n"
                    read -r -p "是否重新安装？[y/n]:" reInstallStatus
                    if [[ "${reInstallStatus}" == "y" ]]; then
                        rm -rf /etc/v2ray-agent/tls/*
                        installTLS "$1"
                    fi
                fi
            fi
        fi

    elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
        switchDNSAPI
        if [[ -z "${dnsAPIType}" ]]; then
            echoContent yellow "\n ---> 不采用API申请证书"
            echoContent green " ---> 安装TLS证书，需要依赖80端口"
            allowPort 80
        fi

        switchSSLType
        customSSLEmail
        selectAcmeInstallSSL

        if [[ "${installedDNSAPIStatus}" == "true" ]]; then
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
        else
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
        fi

        if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
            tail -n 10 /etc/v2ray-agent/tls/acme.log
            if [[ ${installTLSCount} == "1" ]]; then
                echoContent red " ---> TLS安装失败，请检查acme日志"
                exit 0
            fi

            installTLSCount=1
            echo

            if tail -n 10 /etc/v2ray-agent/tls/acme.log | grep -q "Could not validate email address as valid"; then
                echoContent red " ---> 邮箱无法通过SSL厂商验证，请重新输入"
                echo
                customSSLEmail "validate email"
                installTLS "$1"
            else
                installTLS "$1"
            fi
        fi

        echoContent green " ---> TLS生成成功"
    else
        echoContent yellow " ---> 未安装acme.sh"
        exit 0
    fi
}

# 初始化随机字符串
initRandomPath() {
    local chars="abcdefghijklmnopqrtuxyz"
    local initCustomPath=
    for i in {1..4}; do
        echo "${i}" >/dev/null
        initCustomPath+="${chars:RANDOM%${#chars}:1}"
    done
    customPath=${initCustomPath}
}

# 自定义/随机路径
randomPathFunction() {
    if [[ -n $1 ]]; then
        echoContent skyBlue "\n进度  $1/${totalProgress} : 生成随机路径"
    else
        echoContent skyBlue "生成随机路径"
    fi

    if [[ -n "${currentPath}" && -z "${lastInstallationConfig}" ]]; then
        echo
        read -r -p "读取到上次安装记录，是否使用上次安装时的path路径 ？[y/n]:" historyPathStatus
        echo
    elif [[ -n "${currentPath}" && -n "${lastInstallationConfig}" ]]; then
        historyPathStatus="y"
    fi

    if [[ "${historyPathStatus}" == "y" ]]; then
        customPath=${currentPath}
        echoContent green " ---> 使用成功\n"
    else
        echoContent yellow "请输入自定义路径[例: alone]，不需要斜杠，[回车]随机路径"
        read -r -p '路径:' customPath
        if [[ -z "${customPath}" ]]; then
            initRandomPath
            currentPath=${customPath}
        else
            if [[ "${customPath: -2}" == "ws" ]]; then
                echo
                echoContent red " ---> 自定义path结尾不可用ws结尾，否则无法区分分流路径"
                randomPathFunction "$1"
            else
                currentPath=${customPath}
            fi
        fi
    fi
    echoContent yellow "\n path:${currentPath}"
    echoContent skyBlue "\n----------------------------"
}
# 随机数
randomNum() {
    if [[ "${release}" == "alpine" ]]; then
        local ranNum=
        ranNum="$(shuf -i "$1"-"$2" -n 1)"
        echo "${ranNum}"
    else
        echo $((RANDOM % $2 + $1))
    fi
}
# Nginx伪装博客
nginxBlog() {
    if [[ -n "$1" ]]; then
        echoContent skyBlue "\n进度 $1/${totalProgress} : 添加伪装站点"
    else
        echoContent yellow "\n开始添加伪装站点"
    fi

    if [[ -d "${nginxStaticPath}" && -f "${nginxStaticPath}/check" ]]; then
        echo
        if [[ -z "${lastInstallationConfig}" ]]; then
            read -r -p "检测到安装伪装站点，是否需要重新安装[y/n]:" nginxBlogInstallStatus
        else
            nginxBlogInstallStatus="n"
        fi

        if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
            rm -rf "${nginxStaticPath}*"
            #  randomNum=$((RANDOM % 6 + 1))
            randomNum=$(randomNum 1 9)
            if [[ "${release}" == "alpine" ]]; then
                wget -q -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
            else
                wget -q "${wgetShowProgressStatus}" -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
            fi

            unzip -o "${nginxStaticPath}html${randomNum}.zip" -d "${nginxStaticPath}" >/dev/null
            rm -f "${nginxStaticPath}html${randomNum}.zip*"
            echoContent green " ---> 添加伪装站点成功"
        fi
    else
        randomNum=$(randomNum 1 9)
        #        randomNum=$((RANDOM % 6 + 1))
        rm -rf "${nginxStaticPath}*"

        if [[ "${release}" == "alpine" ]]; then
            wget -q -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
        else
            wget -q "${wgetShowProgressStatus}" -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
        fi

        unzip -o "${nginxStaticPath}html${randomNum}.zip" -d "${nginxStaticPath}" >/dev/null
        rm -f "${nginxStaticPath}html${randomNum}.zip*"
        echoContent green " ---> 添加伪装站点成功"
    fi

}

# 修改http_port_t端口
updateSELinuxHTTPPortT() {

    $(find /usr/bin /usr/sbin | grep -w journalctl) -xe >/etc/v2ray-agent/nginx_error.log 2>&1

    if find /usr/bin /usr/sbin | grep -q -w semanage && find /usr/bin /usr/sbin | grep -q -w getenforce && grep -E "31300|31302" </etc/v2ray-agent/nginx_error.log | grep -q "Permission denied"; then
        echoContent red " ---> 检查SELinux端口是否开放"
        if ! $(find /usr/bin /usr/sbin | grep -w semanage) port -l | grep http_port | grep -q 31300; then
            $(find /usr/bin /usr/sbin | grep -w semanage) port -a -t http_port_t -p tcp 31300
            echoContent green " ---> http_port_t 31300 端口开放成功"
        fi

        if ! $(find /usr/bin /usr/sbin | grep -w semanage) port -l | grep http_port | grep -q 31302; then
            $(find /usr/bin /usr/sbin | grep -w semanage) port -a -t http_port_t -p tcp 31302
            echoContent green " ---> http_port_t 31302 端口开放成功"
        fi
        handleNginx start

    else
        exit 0
    fi
}

# 操作Nginx
handleNginx() {

    if ! echo "${selectCustomInstallType}" | grep -qwE ",7,|,8,|,7,8," && [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
        if [[ "${release}" == "alpine" ]]; then
            rc-service nginx start 2>/etc/v2ray-agent/nginx_error.log
        else
            systemctl start nginx 2>/etc/v2ray-agent/nginx_error.log
        fi

        sleep 0.5

        if [[ -z $(pgrep -f "nginx") ]]; then
            echoContent red " ---> Nginx启动失败"
            echoContent red " ---> 请将下方日志反馈给开发者"
            nginx
            if grep -q "journalctl -xe" </etc/v2ray-agent/nginx_error.log; then
                updateSELinuxHTTPPortT
            fi
        else
            echoContent green " ---> Nginx启动成功"
        fi

    elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then

        if [[ "${release}" == "alpine" ]]; then
            rc-service nginx stop
        else
            systemctl stop nginx
        fi
        sleep 0.5

        if [[ -z ${btDomain} && -n $(pgrep -f "nginx") ]]; then
            pgrep -f "nginx" | xargs kill -9
        fi
        echoContent green " ---> Nginx关闭成功"
    fi
}

# 定时任务更新tls证书
installCronTLS() {
    if [[ -z "${btDomain}" ]]; then
        echoContent skyBlue "\n进度 $1/${totalProgress} : 添加定时维护证书"
        crontab -l >/etc/v2ray-agent/backup_crontab.cron
        local historyCrontab
        historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d' /etc/v2ray-agent/backup_crontab.cron)
        echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
        echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
        crontab /etc/v2ray-agent/backup_crontab.cron
        echoContent green "\n ---> 添加定时维护证书成功"
    fi
}
# 定时任务更新geo文件 (已移除，仅Xray需要)
installCronUpdateGeo() {
    :
}

# 更新证书
renewalTLS() {

    if [[ -n $1 ]]; then
        echoContent skyBlue "\n进度  $1/1 : 更新证书"
    fi
    readAcmeTLS
    local domain=${currentHost}
    if [[ -z "${currentHost}" && -n "${tlsDomain}" ]]; then
        domain=${tlsDomain}
    fi

    if [[ -f "/etc/v2ray-agent/tls/ssl_type" ]]; then
        if grep -q "buypass" <"/etc/v2ray-agent/tls/ssl_type"; then
            sslRenewalDays=180
        fi
    fi
    if [[ -d "$HOME/.acme.sh/${domain}_ecc" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
        modifyTime=

        if [[ "${installedDNSAPIStatus}" == "true" ]]; then
            modifyTime=$(stat --format=%z "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer")
        else
            modifyTime=$(stat --format=%z "$HOME/.acme.sh/${domain}_ecc/${domain}.cer")
        fi

        modifyTime=$(date +%s -d "${modifyTime}")
        currentTime=$(date +%s)
        ((stampDiff = currentTime - modifyTime))
        ((days = stampDiff / 86400))
        ((remainingDays = sslRenewalDays - days))

        tlsStatus=${remainingDays}
        if [[ ${remainingDays} -le 0 ]]; then
            tlsStatus="已过期"
        fi

        echoContent skyBlue " ---> 证书检查日期:$(date "+%F %H:%M:%S")"
        echoContent skyBlue " ---> 证书生成日期:$(date -d @"${modifyTime}" +"%F %H:%M:%S")"
        echoContent skyBlue " ---> 证书生成天数:${days}"
        echoContent skyBlue " ---> 证书剩余天数:"${tlsStatus}
        echoContent skyBlue " ---> 证书过期前最后一天自动更新，如更新失败请手动更新"

        if [[ ${remainingDays} -le 1 ]]; then
            echoContent yellow " ---> 重新生成证书"
            handleNginx stop
            handleSingBox stop

            sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /etc/v2ray-agent/tls/"${domain}.crt" --keypath /etc/v2ray-agent/tls/"${domain}.key" --ecc
            reloadCore
            handleNginx start
        else
            echoContent green " ---> 证书有效"
        fi
    elif [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
        echoContent yellow " ---> 检测到使用自定义证书，无法执行renew操作。"
    else
        echoContent red " ---> 未安装"
    fi
}

# 安装 sing-box
installSingBox() {
    readInstallType
    echoContent skyBlue "\n进度  $1/${totalProgress} : 安装sing-box"

    if [[ ! -f "/etc/v2ray-agent/sing-box/sing-box" ]]; then

        version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)

        echoContent green " ---> 最新版本:${version}"

        if [[ "${release}" == "alpine" ]]; then
            wget -c -q -P /etc/v2ray-agent/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"
        else
            wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"
        fi

        if [[ ! -f "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" ]]; then
            read -r -p "核心下载失败，请重新尝试安装，是否重新尝试？[y/n]" downloadStatus
            if [[ "${downloadStatus}" == "y" ]]; then
                installSingBox "$1"
            fi
        else

            tar zxvf "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" -C "/etc/v2ray-agent/sing-box/" >/dev/null 2>&1

            mv "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}/sing-box" /etc/v2ray-agent/sing-box/sing-box
            rm -rf /etc/v2ray-agent/sing-box/sing-box-*
            chmod 655 /etc/v2ray-agent/sing-box/sing-box
        fi
    else
        echoContent green " ---> 当前版本:v$(/etc/v2ray-agent/sing-box/sing-box version | grep "sing-box version" | awk '{print $3}')"

        version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
        echoContent green " ---> 最新版本:${version}"

        if [[ -z "${lastInstallationConfig}" ]]; then
            read -r -p "是否更新、升级？[y/n]:" reInstallSingBoxStatus
            if [[ "${reInstallSingBoxStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/sing-box/sing-box
                installSingBox "$1"
            fi
        fi
    fi

}

# 检查wget showProgress
checkWgetShowProgress() {
    if [[ "${release}" != "alpine" ]]; then
        if find /usr/bin /usr/sbin | grep -q "/wget" && wget --help | grep -q show-progress; then
            wgetShowProgressStatus="--show-progress"
        fi
    fi
}
# 验证整个服务是否可用
checkGFWStatue() {
    readInstallType
    echoContent skyBlue "\n进度 $1/${totalProgress} : 验证服务启动状态"
    if [[ -n $(pgrep -f "sing-box/sing-box") ]]; then
        echoContent green " ---> 服务启动成功"
    else
        echoContent red " ---> 服务启动失败，请检查终端是否有日志打印"
        exit 0
    fi
}

# 安装alpine开机启动
installAlpineStartup() {
    local serviceName=$1
    if [[ "${serviceName}" == "sing-box" ]]; then
        cat <<EOF >"/etc/init.d/${serviceName}"
#!/sbin/openrc-run

description="sing-box service"
command="/etc/v2ray-agent/sing-box/sing-box"
command_args="run -c /etc/v2ray-agent/sing-box/conf/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF
    fi

    chmod +x "/etc/init.d/${serviceName}"
}

# sing-box开机自启
installSingBoxService() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 配置sing-box开机自启"
    execStart='/etc/v2ray-agent/sing-box/sing-box run -c /etc/v2ray-agent/sing-box/conf/config.json'

    if [[ -n $(find /bin /usr/bin -name "systemctl") && "${release}" != "alpine" ]]; then
        rm -rf /etc/systemd/system/sing-box.service
        touch /etc/systemd/system/sing-box.service
        cat <<EOF >/etc/systemd/system/sing-box.service
[Unit]
Description=Sing-Box Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=${execStart}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNPROC=infinity
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        bootStartup "sing-box.service"
    elif [[ "${release}" == "alpine" ]]; then
        installAlpineStartup "sing-box"
        bootStartup "sing-box"
    fi

    echoContent green " ---> 配置sing-box开机启动完毕"
}

# 操作Hysteria
handleHysteria() {
    # shellcheck disable=SC2010
    if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q hysteria.service; then
        if [[ -z $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "start" ]]; then
            systemctl start hysteria.service
        elif [[ -n $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop hysteria.service
        fi
    fi
    sleep 0.8

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "hysteria/hysteria") ]]; then
            echoContent green " ---> Hysteria启动成功"
        else
            echoContent red "Hysteria启动失败"
            echoContent red "请手动执行【/etc/v2ray-agent/hysteria/hysteria --log-level debug -c /etc/v2ray-agent/hysteria/conf/config.json server】，查看错误日志"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "hysteria/hysteria") ]]; then
            echoContent green " ---> Hysteria关闭成功"
        else
            echoContent red "Hysteria关闭失败"
            echoContent red "请手动执行【ps -ef|grep -v grep|grep hysteria|awk '{print \$2}'|xargs kill -9】"
            exit 0
        fi
    fi
}

# 操作sing-box
handleSingBox() {
    if [[ -f "/etc/systemd/system/sing-box.service" ]]; then
        if [[ -z $(pgrep -f "sing-box") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig
            systemctl start sing-box.service
        elif [[ -n $(pgrep -f "sing-box") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop sing-box.service
        fi
    elif [[ -f "/etc/init.d/sing-box" ]]; then
        if [[ -z $(pgrep -f "sing-box") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig
            rc-service sing-box start
        elif [[ -n $(pgrep -f "sing-box") ]] && [[ "$1" == "stop" ]]; then
            rc-service sing-box stop
        fi
    fi
    sleep 1

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "sing-box") ]]; then
            echoContent green " ---> sing-box启动成功"
        else
            echoContent red "sing-box启动失败"
            echoContent yellow "请手动执行【 /etc/v2ray-agent/sing-box/sing-box merge config.json -C /etc/v2ray-agent/sing-box/conf/config/ -D /etc/v2ray-agent/sing-box/conf/ 】，查看错误日志"
            echo
            echoContent yellow "如上面命令没有错误，请手动执行【 /etc/v2ray-agent/sing-box/sing-box run -c /etc/v2ray-agent/sing-box/conf/config.json 】，查看错误日志"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "sing-box") ]]; then
            echoContent green " ---> sing-box关闭成功"
        else
            echoContent red " ---> sing-box关闭失败"
            echoContent red "请手动执行【ps -ef|grep -v grep|grep sing-box|awk '{print \$2}'|xargs kill -9】"
            exit 0
        fi
    fi
}

initSingBoxClients() {
    local type=",$1,"
    local newUUID=$2
    local newName=$3

    if [[ -n "${newUUID}" ]]; then
        local newUser=
        newUser="{\"uuid\":\"${newUUID}\",\"flow\":\"xtls-rprx-vision\",\"name\":\"${newName}-VLESS_TCP/TLS_Vision\"}"
        currentClients=$(echo "${currentClients}" | jq -r ". +=[${newUser}]")
    fi
    local users=
    users=[]
    while read -r user; do
        uuid=$(echo "${user}" | jq -r .uuid//.id//.password)
        name=$(echo "${user}" | jq -r .name//.email//.username | awk -F "[-]" '{print $1}')
        currentUser=
        # VLESS Vision
        if echo "${type}" | grep -q ",0,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"name\":\"${name}-VLESS_TCP/TLS_Vision\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VLESS WS
        if echo "${type}" | grep -q ",1,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VLESS_WS\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VMess ws
        if echo "${type}" | grep -q ",3,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VMess_WS\",\"alterId\": 0}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # trojan
        if echo "${type}" | grep -q ",4,"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${name}-Trojan_TCP\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # VLESS Reality Vision
        if echo "${type}" | grep -q ",7,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"name\":\"${name}-VLESS_Reality_Vision\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VLESS Reality gRPC
        if echo "${type}" | grep -q ",8,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VLESS_Reality_gPRC\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # hysteria2
        if echo "${type}" | grep -q ",6,"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${name}-singbox_hysteria2\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # tuic
        if echo "${type}" | grep -q ",9,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"password\":\"${uuid}\",\"name\":\"${name}-singbox_tuic\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # naive
        if echo "${type}" | grep -q ",10,"; then
            currentUser="{\"password\":\"${uuid}\",\"username\":\"${name}-singbox_naive\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VMess HTTPUpgrade
        if echo "${type}" | grep -q ",11,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VMess_HTTPUpgrade\",\"alterId\": 0}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # anytls
        if echo "${type}" | grep -q ",13,"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${name}-anytls\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        if echo "${type}" | grep -q ",20,"; then
            currentUser="{\"username\":\"${uuid}\",\"password\":\"${uuid}\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

    done < <(echo "${currentClients}" | jq -c '.[]')
    echo "${users}"
}

# 初始化hysteria端口
initHysteriaPort() {
    readSingBoxConfig
    if [[ -n "${hysteriaPort}" ]]; then
        read -r -p "读取到上次安装时的端口，是否使用上次安装时的端口？[y/n]:" historyHysteriaPortStatus
        if [[ "${historyHysteriaPortStatus}" == "y" ]]; then
            echoContent yellow "\n ---> 端口: ${hysteriaPort}"
        else
            hysteriaPort=
        fi
    fi

    if [[ -z "${hysteriaPort}" ]]; then
        echoContent yellow "请输入Hysteria端口[回车随机10000-30000]，不可与其他服务重复"
        read -r -p "端口:" hysteriaPort
        if [[ -z "${hysteriaPort}" ]]; then
            hysteriaPort=$((RANDOM % 20001 + 10000))
        fi
    fi
    if [[ -z ${hysteriaPort} ]]; then
        echoContent red " ---> 端口不可为空"
        initHysteriaPort "$2"
    elif ((hysteriaPort < 1 || hysteriaPort > 65535)); then
        echoContent red " ---> 端口不合法"
        initHysteriaPort "$2"
    fi
    allowPort "${hysteriaPort}"
    allowPort "${hysteriaPort}" "udp"
}

# 初始化hysteria网络信息
initHysteria2Network() {

    echoContent yellow "请输入本地带宽峰值的下行速度（默认：100，单位：Mbps）"
    read -r -p "下行速度:" hysteria2ClientDownloadSpeed
    if [[ -z "${hysteria2ClientDownloadSpeed}" ]]; then
        hysteria2ClientDownloadSpeed=100
        echoContent green "\n ---> 下行速度: ${hysteria2ClientDownloadSpeed}\n"
    fi

    echoContent yellow "请输入本地带宽峰值的上行速度（默认：50，单位：Mbps）"
    read -r -p "上行速度:" hysteria2ClientUploadSpeed
    if [[ -z "${hysteria2ClientUploadSpeed}" ]]; then
        hysteria2ClientUploadSpeed=50
        echoContent green "\n ---> 上行速度: ${hysteria2ClientUploadSpeed}\n"
    fi
}

# firewalld设置端口跳跃
addFirewalldPortHopping() {

    local start=$1
    local end=$2
    local targetPort=$3
    for port in $(seq "$start" "$end"); do
        sudo firewall-cmd --permanent --add-forward-port=port="${port}":proto=udp:toport="${targetPort}"
    done
    sudo firewall-cmd --reload
}

# 端口跳跃
addPortHopping() {
    local type=$1
    local targetPort=$2
    if [[ -n "${portHoppingStart}" || -n "${portHoppingEnd}" ]]; then
        echoContent red " ---> 已添加不可重复添加，可删除后重新添加"
        exit 0
    fi
    if [[ "${release}" == "centos" ]]; then
        if ! systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
            echoContent red " ---> 未启动firewalld防火墙，无法设置端口跳跃。"
            exit 0
        fi
    fi

    echoContent skyBlue "\n进度 1/1 : 端口跳跃"
    echoContent red "\n=============================================================="
    echoContent yellow "# 注意事项\n"
    echoContent yellow "仅支持Hysteria2、Tuic"
    echoContent yellow "端口跳跃的起始位置为30000"
    echoContent yellow "端口跳跃的结束位置为40000"
    echoContent yellow "可以在30000-40000范围中选一段"
    echoContent yellow "建议1000个左右"
    echoContent yellow "注意不要和其他的端口跳跃设置范围一样，设置相同会覆盖。"

    echoContent yellow "请输入端口跳跃的范围，例如[30000-31000]"

    read -r -p "范围:" portHoppingRange
    if [[ -z "${portHoppingRange}" ]]; then
        echoContent red " ---> 范围不可为空"
        addPortHopping "${type}" "${targetPort}"
    elif echo "${portHoppingRange}" | grep -q "-"; then

        local portStart=
        local portEnd=
        portStart=$(echo "${portHoppingRange}" | awk -F '-' '{print $1}')
        portEnd=$(echo "${portHoppingRange}" | awk -F '-' '{print $2}')

        if [[ -z "${portStart}" || -z "${portEnd}" ]]; then
            echoContent red " ---> 范围不合法"
            addPortHopping "${type}" "${targetPort}"
        elif ((portStart < 30000 || portStart > 40000 || portEnd < 30000 || portEnd > 40000 || portEnd < portStart)); then
            echoContent red " ---> 范围不合法"
            addPortHopping "${type}" "${targetPort}"
        else
            echoContent green "\n端口范围: ${portHoppingRange}\n"
            if [[ "${release}" == "centos" ]]; then
                sudo firewall-cmd --permanent --add-masquerade
                sudo firewall-cmd --reload
                addFirewalldPortHopping "${portStart}" "${portEnd}" "${targetPort}"
                if ! sudo firewall-cmd --list-forward-ports | grep -q "toport=${targetPort}"; then
                    echoContent red " ---> 端口跳跃添加失败"
                    exit 0
                fi
            else
                iptables -t nat -A PREROUTING -p udp --dport "${portStart}:${portEnd}" -m comment --comment "mack-a_${type}_portHopping" -j DNAT --to-destination ":${targetPort}"
                sudo netfilter-persistent save
                if ! iptables-save | grep -q "mack-a_${type}_portHopping"; then
                    echoContent red " ---> 端口跳跃添加失败"
                    exit 0
                fi
            fi
            allowPort "${portStart}:${portEnd}" udp
            echoContent green " ---> 端口跳跃添加成功"
        fi
    fi
}

# 读取端口跳跃的配置
readPortHopping() {
    local type=$1
    local targetPort=$2
    local portHoppingStart=
    local portHoppingEnd=

    if [[ "${release}" == "centos" ]]; then
        portHoppingStart=$(sudo firewall-cmd --list-forward-ports | grep "toport=${targetPort}" | head -1 | cut -d ":" -f 1 | cut -d "=" -f 2)
        portHoppingEnd=$(sudo firewall-cmd --list-forward-ports | grep "toport=${targetPort}" | tail -n 1 | cut -d ":" -f 1 | cut -d "=" -f 2)
    else
        if iptables-save | grep -q "mack-a_${type}_portHopping"; then
            local portHopping=
            portHopping=$(iptables-save | grep "mack-a_${type}_portHopping" | cut -d " " -f 8)

            portHoppingStart=$(echo "${portHopping}" | cut -d ":" -f 1)
            portHoppingEnd=$(echo "${portHopping}" | cut -d ":" -f 2)
        fi
    fi
    if [[ "${type}" == "hysteria2" ]]; then
        hysteria2PortHoppingStart="${portHoppingStart}"
        hysteria2PortHoppingEnd=${portHoppingEnd}
        hysteria2PortHopping="${portHoppingStart}-${portHoppingEnd}"
    elif [[ "${type}" == "tuic" ]]; then
        tuicPortHoppingStart="${portHoppingStart}"
        tuicPortHoppingEnd="${portHoppingEnd}"
        #        tuicPortHopping="${portHoppingStart}-${portHoppingEnd}"
    fi
}
# 删除端口跳跃iptables规则
deletePortHoppingRules() {
    local type=$1
    local start=$2
    local end=$3
    local targetPort=$4

    if [[ "${release}" == "centos" ]]; then
        for port in $(seq "${start}" "${end}"); do
            sudo firewall-cmd --permanent --remove-forward-port=port="${port}":proto=udp:toport="${targetPort}"
        done
        sudo firewall-cmd --reload
    else
        iptables -t nat -L PREROUTING --line-numbers | grep "mack-a_${type}_portHopping" | awk '{print $1}' | while read -r line; do
            iptables -t nat -D PREROUTING 1
            sudo netfilter-persistent save
        done
    fi
}

# 端口跳跃菜单
portHoppingMenu() {
    local type=$1
    # 判断iptables是否存在
    if ! find /usr/bin /usr/sbin | grep -q -w iptables; then
        echoContent red " ---> 无法识别iptables工具，无法使用端口跳跃，退出安装"
        exit 0
    fi

    local targetPort=
    local portHoppingStart=
    local portHoppingEnd=

    if [[ "${type}" == "hysteria2" ]]; then
        readPortHopping "${type}" "${singBoxHysteria2Port}"
        targetPort=${singBoxHysteria2Port}
        portHoppingStart=${hysteria2PortHoppingStart}
        portHoppingEnd=${hysteria2PortHoppingEnd}
    elif [[ "${type}" == "tuic" ]]; then
        readPortHopping "${type}" "${singBoxTuicPort}"
        targetPort=${singBoxTuicPort}
        portHoppingStart=${tuicPortHoppingStart}
        portHoppingEnd=${tuicPortHoppingEnd}
    fi

    echoContent skyBlue "\n进度 1/1 : 端口跳跃"
    echoContent red "\n=============================================================="
    echoContent yellow "1.添加端口跳跃"
    echoContent yellow "2.删除端口跳跃"
    echoContent yellow "3.查看端口跳跃"
    read -r -p "请选择:" selectPortHoppingStatus
    if [[ "${selectPortHoppingStatus}" == "1" ]]; then
        addPortHopping "${type}" "${targetPort}"
    elif [[ "${selectPortHoppingStatus}" == "2" ]]; then
        deletePortHoppingRules "${type}" "${portHoppingStart}" "${portHoppingEnd}" "${targetPort}"
        echoContent green " ---> 删除成功"
    elif [[ "${selectPortHoppingStatus}" == "3" ]]; then
        if [[ -n "${portHoppingStart}" && -n "${portHoppingEnd}" ]]; then
            echoContent green " ---> 当前端口跳跃范围为: ${portHoppingStart}-${portHoppingEnd}"
        else
            echoContent yellow " ---> 未设置端口跳跃"
        fi
    else
        portHoppingMenu
    fi
}

# 初始化tuic端口
initTuicPort() {
    readSingBoxConfig
    if [[ -n "${tuicPort}" ]]; then
        read -r -p "读取到上次安装时的端口，是否使用上次安装时的端口？[y/n]:" historyTuicPortStatus
        if [[ "${historyTuicPortStatus}" == "y" ]]; then
            echoContent yellow "\n ---> 端口: ${tuicPort}"
        else
            tuicPort=
        fi
    fi

    if [[ -z "${tuicPort}" ]]; then
        echoContent yellow "请输入Tuic端口[回车随机10000-30000]，不可与其他服务重复"
        read -r -p "端口:" tuicPort
        if [[ -z "${tuicPort}" ]]; then
            tuicPort=$((RANDOM % 20001 + 10000))
        fi
    fi
    if [[ -z ${tuicPort} ]]; then
        echoContent red " ---> 端口不可为空"
        initTuicPort "$2"
    elif ((tuicPort < 1 || tuicPort > 65535)); then
        echoContent red " ---> 端口不合法"
        initTuicPort "$2"
    fi
    echoContent green "\n ---> 端口: ${tuicPort}"
    allowPort "${tuicPort}"
    allowPort "${tuicPort}" "udp"
}

# 初始化tuic的协议
initTuicProtocol() {
    if [[ -n "${tuicAlgorithm}" && -z "${lastInstallationConfig}" ]]; then
        read -r -p "读取到上次使用的算法，是否使用 ？[y/n]:" historyTuicAlgorithm
        if [[ "${historyTuicAlgorithm}" != "y" ]]; then
            tuicAlgorithm=
        else
            echoContent yellow "\n ---> 算法: ${tuicAlgorithm}\n"
        fi
    elif [[ -n "${tuicAlgorithm}" && -n "${lastInstallationConfig}" ]]; then
        echoContent yellow "\n ---> 算法: ${tuicAlgorithm}\n"
    fi

    if [[ -z "${tuicAlgorithm}" ]]; then

        echoContent skyBlue "\n请选择算法类型"
        echoContent red "=============================================================="
        echoContent yellow "1.bbr(默认)"
        echoContent yellow "2.cubic"
        echoContent yellow "3.new_reno"
        echoContent red "=============================================================="
        read -r -p "请选择:" selectTuicAlgorithm
        case ${selectTuicAlgorithm} in
        1)
            tuicAlgorithm="bbr"
            ;;
        2)
            tuicAlgorithm="cubic"
            ;;
        3)
            tuicAlgorithm="new_reno"
            ;;
        *)
            tuicAlgorithm="bbr"
            ;;
        esac
        echoContent yellow "\n ---> 算法: ${tuicAlgorithm}\n"
    fi
}
# 初始化singbox route配置
initSingBoxRouteConfig() {
    downloadSingBoxGeositeDB
    local outboundTag=$1
    if [[ ! -f "${singBoxConfigPath}${outboundTag}_route.json" ]]; then
        cat <<EOF >"${singBoxConfigPath}${outboundTag}_route.json"
{
    "route": {
        "geosite": {
            "path": "${singBoxConfigPath}geosite.db"
        },
        "rules": [
            {
                "domain": [
                ],
                "geosite": [
                ],
                "outbound": "${outboundTag}"
            }
        ]
    }
}
EOF
    fi
}
# 下载sing-box geosite db
downloadSingBoxGeositeDB() {
    if [[ ! -f "${singBoxConfigPath}geosite.db" ]]; then
        if [[ "${release}" == "alpine" ]]; then
            wget -q -P "${singBoxConfigPath}" https://github.com/Johnshall/sing-geosite/releases/latest/download/geosite.db
        else
            wget -q "${wgetShowProgressStatus}" -P "${singBoxConfigPath}" https://github.com/Johnshall/sing-geosite/releases/latest/download/geosite.db
        fi

    fi
}

# 添加sing-box路由规则
addSingBoxRouteRule() {
    local outboundTag=$1
    # 域名列表
    local domainList=$2
    # 路由文件名称
    local routingName=$3
    # 读取上次安装内容
    if [[ -f "${singBoxConfigPath}${routingName}.json" ]]; then
        read -r -p "读取到上次的配置，是否保留 ？[y/n]:" historyRouteStatus
        if [[ "${historyRouteStatus}" == "y" ]]; then
            domainList="${domainList},$(jq -rc .route.rules[0].rule_set[] "${singBoxConfigPath}${routingName}.json" | awk -F "[_]" '{print $1}' | paste -sd ',')"
            domainList="${domainList},$(jq -rc .route.rules[0].domain_regex[] "${singBoxConfigPath}${routingName}.json" | awk -F "[*]" '{print $2}' | paste -sd ',' | sed 's/\\//g')"
        fi
    fi
    local rules=
    rules=$(initSingBoxRules "${domainList}" "${routingName}")
    # domain精确匹配规则
    local domainRules=
    domainRules=$(echo "${rules}" | jq .domainRules)

    # ruleSet规则集
    local ruleSet=
    ruleSet=$(echo "${rules}" | jq .ruleSet)

    # ruleSet规则tag
    local ruleSetTag=[]
    if [[ "$(echo "${ruleSet}" | jq '.|length')" != "0" ]]; then
        ruleSetTag=$(echo "${ruleSet}" | jq '.|map(.tag)')
    fi
    if [[ -n "${singBoxConfigPath}" ]]; then

        cat <<EOF >"${singBoxConfigPath}${routingName}.json"
{
  "route": {
    "rules": [
      {
        "rule_set":${ruleSetTag},
        "domain_regex":${domainRules},
        "outbound": "${outboundTag}"
      }
    ],
    "rule_set":${ruleSet}
  }
}
EOF
        jq 'if .route.rule_set == [] then del(.route.rule_set) else . end' "${singBoxConfigPath}${routingName}.json" >"${singBoxConfigPath}${routingName}_tmp.json" && mv "${singBoxConfigPath}${routingName}_tmp.json" "${singBoxConfigPath}${routingName}.json"
    fi

}

# 移除sing-box route rule
removeSingBoxRouteRule() {
    local outboundTag=$1
    local delRules
    if [[ -f "${singBoxConfigPath}${outboundTag}_route.json" ]]; then
        delRules=$(jq -r 'del(.route.rules[]|select(.outbound=="'"${outboundTag}"'"))' "${singBoxConfigPath}${outboundTag}_route.json")
        echo "${delRules}" >"${singBoxConfigPath}${outboundTag}_route.json"
    fi
}

# 添加sing-box出站
addSingBoxOutbound() {
    local tag=$1
    local type="ipv4"
    local detour=$2
    if echo "${tag}" | grep -q "IPv6"; then
        type=ipv6
    fi
    if [[ -n "${detour}" ]]; then
        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}",
             "detour": "${detour}",
             "domain_strategy": "${type}_only"
        }
    ]
}
EOF
    elif echo "${tag}" | grep -q "direct"; then

        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}"
        }
    ]
}
EOF
    elif echo "${tag}" | grep -q "block"; then

        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "block",
             "tag": "${tag}"
        }
    ]
}
EOF
    else
        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}",
             "domain_strategy": "${type}_only"
        }
    ]
}
EOF
    fi
}

# 移除sing-box配置
removeSingBoxConfig() {

    local tag=$1
    if [[ -f "${singBoxConfigPath}${tag}.json" ]]; then
        rm "${singBoxConfigPath}${tag}.json"
    fi
}

# 初始化wireguard出站信息
addSingBoxWireGuardEndpoints() {
    local type=$1

    readConfigWarpReg

    cat <<EOF >"${singBoxConfigPath}wireguard_endpoints_${type}.json"
{
     "endpoints": [
        {
            "type": "wireguard",
            "tag": "wireguard_endpoints_${type}",
            "address": [
                "${address}"
            ],
            "private_key": "${secretKeyWarpReg}",
            "peers": [
                {
                  "address": "162.159.192.1",
                  "port": 2408,
                  "public_key": "${publicKeyWarpReg}",
                  "reserved":${reservedWarpReg},
                  "allowed_ips": ["0.0.0.0/0","::/0"]
                }
            ]
        }
    ]
}
EOF
}

# 初始化 sing-box Hysteria2 配置
initSingBoxHysteria2Config() {
    echoContent skyBlue "\n进度 $1/${totalProgress} : 初始化Hysteria2配置"

    initHysteriaPort
    initHysteria2Network

    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/hysteria2.json
{
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": ${hysteriaPort},
            "users": $(initSingBoxClients 6),
            "up_mbps":${hysteria2ClientDownloadSpeed},
            "down_mbps":${hysteria2ClientUploadSpeed},
            "tls": {
                "enabled": true,
                "server_name":"${currentHost}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${currentHost}.crt",
                "key_path": "/etc/v2ray-agent/tls/${currentHost}.key"
            }
        }
    ]
}
EOF
}

# sing-box Tuic安装
singBoxTuicInstall() {
    if ! echo "${currentInstallProtocolType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,"; then
        echoContent red "\n ---> 由于需要依赖证书，如安装Tuic，请先安装带有TLS标识协议"
        exit 0
    fi

    totalProgress=5
    installSingBox 1
    selectCustomInstallType=",9,"
    initSingBoxConfig custom 2 true
    installSingBoxService 3
    reloadCore
    showAccounts 4
}

# sing-box hy2安装
singBoxHysteria2Install() {
    if ! echo "${currentInstallProtocolType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,"; then
        echoContent red "\n ---> 由于需要依赖证书，如安装Hysteria2，请先安装带有TLS标识协议"
        exit 0
    fi

    totalProgress=5
    installSingBox 1
    selectCustomInstallType=",6,"
    initSingBoxConfig custom 2 true
    installSingBoxService 3
    reloadCore
    showAccounts 4
}

# 合并config
singBoxMergeConfig() {
    rm /etc/v2ray-agent/sing-box/conf/config.json >/dev/null 2>&1
    /etc/v2ray-agent/sing-box/sing-box merge config.json -C /etc/v2ray-agent/sing-box/conf/config/ -D /etc/v2ray-agent/sing-box/conf/ >/dev/null 2>&1
}

# 初始化sing-box端口
initSingBoxPort() {
    local port=$1
    if [[ -n "${port}" && -z "${lastInstallationConfig}" ]]; then
        read -r -p "读取到上次使用的端口，是否使用 ？[y/n]:" historyPort
        if [[ "${historyPort}" != "y" ]]; then
            port=
        else
            echo "${port}"
        fi
    elif [[ -n "${port}" && -n "${lastInstallationConfig}" ]]; then
        echo "${port}"
    fi
    if [[ -z "${port}" ]]; then
        read -r -p '请输入自定义端口[需合法]，端口不可重复，[回车]随机端口:' port
        if [[ -z "${port}" ]]; then
            port=$((RANDOM % 50001 + 10000))
        fi
        if ((port >= 1 && port <= 65535)); then
            allowPort "${port}"
            allowPort "${port}" "udp"
            echo "${port}"
        else
            echoContent red " ---> 端口输入错误"
            exit 0
        fi
    fi
}

# 初始化TCP Brutal
initTCPBrutal() {
    echoContent skyBlue "\n进度 $2/${totalProgress} : 初始化TCP_Brutal配置"
    read -r -p "是否使用TCP_Brutal？[y/n]:" tcpBrutalStatus
    if [[ "${tcpBrutalStatus}" == "y" ]]; then
        read -r -p "请输入本地带宽峰值的下行速度（默认：100，单位：Mbps）:" tcpBrutalClientDownloadSpeed
        if [[ -z "${tcpBrutalClientDownloadSpeed}" ]]; then
            tcpBrutalClientDownloadSpeed=100
        fi

        read -r -p "请输入本地带宽峰值的上行速度（默认：50，单位：Mbps）:" tcpBrutalClientUploadSpeed
        if [[ -z "${tcpBrutalClientUploadSpeed}" ]]; then
            tcpBrutalClientUploadSpeed=50
        fi
    fi
}
# 初始化sing-box配置文件
initSingBoxConfig() {
    echoContent skyBlue "\n进度 $2/${totalProgress} : 初始化sing-box配置"

    echo
    local uuid=
    local addClientsStatus=
    local sslDomain=
    if [[ -n "${domain}" ]]; then
        sslDomain="${domain}"
    elif [[ -n "${currentHost}" ]]; then
        sslDomain="${currentHost}"
    fi
    if [[ -n "${currentUUID}" && -z "${lastInstallationConfig}" ]]; then
        read -r -p "读取到上次用户配置，是否使用上次安装的配置 ？[y/n]:" historyUUIDStatus
        if [[ "${historyUUIDStatus}" == "y" ]]; then
            addClientsStatus=true
            echoContent green "\n ---> 使用成功"
        fi
    elif [[ -n "${currentUUID}" && -n "${lastInstallationConfig}" ]]; then
        addClientsStatus=true
    fi

    if [[ -z "${addClientsStatus}" ]]; then
        echoContent yellow "请输入自定义UUID[需合法]，[回车]随机UUID"
        read -r -p 'UUID:' customUUID

        if [[ -n ${customUUID} ]]; then
            uuid=${customUUID}
        else
            uuid=$(/etc/v2ray-agent/sing-box/sing-box generate uuid)
        fi

        echoContent yellow "\n请输入自定义用户名[需合法]，[回车]随机用户名"
        read -r -p '用户名:' customEmail
        if [[ -z ${customEmail} ]]; then
            customEmail="$(echo "${uuid}" | cut -d "-" -f 1)-VLESS_TCP/TLS_Vision"
        fi
    fi

    if [[ -z "${addClientsStatus}" && -z "${uuid}" ]]; then
        addClientsStatus=
        echoContent red "\n ---> uuid读取错误，随机生成"
        uuid=$(/etc/v2ray-agent/sing-box/sing-box generate uuid)
    fi

    if [[ -n "${uuid}" ]]; then
        currentClients='[{"uuid":"'${uuid}'","flow":"xtls-rprx-vision","name":"'${customEmail}'"}]'
        echoContent yellow "\n ${customEmail}:${uuid}"
    fi

    # VLESS Vision
    if echo "${selectCustomInstallType}" | grep -q ",0," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== 配置VLESS+Vision =====================\n"
        echoContent skyBlue "\n开始配置VLESS+Vision协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVLESSVisionPort}")
        echoContent green "\n ---> VLESS_Vision端口：${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop

        checkPortOpen "${result[-1]}" "${domain}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/02_VLESS_TCP_inbounds.json
{
    "inbounds":[
        {
          "type": "vless",
          "listen":"::",
          "listen_port":${result[-1]},
          "tag":"VLESSTCP",
          "users":$(initSingBoxClients 0),
          "tls":{
            "server_name": "${sslDomain}",
            "enabled": true,
            "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
            "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/02_VLESS_TCP_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",1," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== 配置VLESS+WS =====================\n"
        echoContent skyBlue "\n开始配置VLESS+WS协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVLESSWSPort}")
        echoContent green "\n ---> VLESS_WS端口：${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop
        randomPathFunction
        checkPortOpen "${result[-1]}" "${domain}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/03_VLESS_WS_inbounds.json
{
    "inbounds":[
        {
          "type": "vless",
          "listen":"::",
          "listen_port":${result[-1]},
          "tag":"VLESSWS",
          "users":$(initSingBoxClients 1),
          "tls":{
            "server_name": "${sslDomain}",
            "enabled": true,
            "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
            "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
          },
          "transport": {
            "type": "ws",
            "path": "/${currentPath}ws",
            "max_early_data": 2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/03_VLESS_WS_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",3," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== 配置VMess+ws =====================\n"
        echoContent skyBlue "\n开始配置VMess+ws协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVMessWSPort}")
        echoContent green "\n ---> VMess_ws端口：${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop
        randomPathFunction
        checkPortOpen "${result[-1]}" "${domain}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/05_VMess_WS_inbounds.json
{
    "inbounds":[
        {
          "type": "vmess",
          "listen":"::",
          "listen_port":${result[-1]},
          "tag":"VMessWS",
          "users":$(initSingBoxClients 3),
          "tls":{
            "server_name": "${sslDomain}",
            "enabled": true,
            "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
            "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
          },
          "transport": {
            "type": "ws",
            "path": "/${currentPath}",
            "max_early_data": 2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/05_VMess_WS_inbounds.json >/dev/null 2>&1
    fi

    # VLESS_Reality_Vision
    if echo "${selectCustomInstallType}" | grep -q ",7," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================= 配置VLESS+Reality+Vision =================\n"
        initRealityClientServersName
        initRealityKey
        echoContent skyBlue "\n开始配置VLESS+Reality+Vision协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVLESSRealityVisionPort}")
        echoContent green "\n ---> VLESS_Reality_Vision端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/07_VLESS_vision_reality_inbounds.json
{
  "inbounds": [
    {
      "type": "vless",
      "listen":"::",
      "listen_port":${result[-1]},
      "tag": "VLESSReality",
      "users":$(initSingBoxClients 7),
      "tls": {
        "enabled": true,
        "server_name": "${realityServerName}",
        "reality": {
            "enabled": true,
            "handshake":{
                "server": "${realityServerName}",
                "server_port":${realityDomainPort}
            },
            "private_key": "${realityPrivateKey}",
            "short_id": [
                "",
                "6ba85179e30d4fc2"
            ]
        }
      }
    }
  ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/07_VLESS_vision_reality_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",8," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置VLESS+Reality+gRPC ==================\n"
        initRealityClientServersName
        initRealityKey
        echoContent skyBlue "\n开始配置VLESS+Reality+gRPC协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVLESSRealityGRPCPort}")
        echoContent green "\n ---> VLESS_Reality_gPRC端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/08_VLESS_vision_gRPC_inbounds.json
{
  "inbounds": [
    {
      "type": "vless",
      "listen":"::",
      "listen_port":${result[-1]},
      "users":$(initSingBoxClients 8),
      "tag": "VLESSRealityGRPC",
      "tls": {
        "enabled": true,
        "server_name": "${realityServerName}",
        "reality": {
            "enabled": true,
            "handshake":{
                "server":"${realityServerName}",
                "server_port":${realityDomainPort}
            },
            "private_key": "${realityPrivateKey}",
            "short_id": [
                "",
                "6ba85179e30d4fc2"
            ]
        }
      },
      "transport": {
          "type": "grpc",
          "service_name": "grpc"
      }
    }
  ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/08_VLESS_vision_gRPC_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",6," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置 Hysteria2 ==================\n"
        echoContent skyBlue "\n开始配置Hysteria2协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxHysteria2Port}")
        echoContent green "\n ---> Hysteria2端口：${result[-1]}"
        initHysteria2Network
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json
{
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 6),
            "up_mbps":${hysteria2ClientDownloadSpeed},
            "down_mbps":${hysteria2ClientUploadSpeed},
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",4," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置 Trojan ==================\n"
        echoContent skyBlue "\n开始配置Trojan协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxTrojanPort}")
        echoContent green "\n ---> Trojan端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/04_trojan_TCP_inbounds.json
{
    "inbounds": [
        {
            "type": "trojan",
            "listen": "::",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 4),
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/04_trojan_TCP_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",9," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n==================== 配置 Tuic =====================\n"
        echoContent skyBlue "\n开始配置Tuic协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxTuicPort}")
        echoContent green "\n ---> Tuic端口：${result[-1]}"
        initTuicProtocol
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json
{
     "inbounds": [
        {
            "type": "tuic",
            "listen": "::",
            "tag": "singbox-tuic-in",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 9),
            "congestion_control": "${tuicAlgorithm}",
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",10," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n==================== 配置 Naive =====================\n"
        echoContent skyBlue "\n开始配置Naive协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxNaivePort}")
        echoContent green "\n ---> Naive端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/10_naive_inbounds.json
{
     "inbounds": [
        {
            "type": "naive",
            "listen": "::",
            "tag": "singbox-naive-in",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 10),
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/10_naive_inbounds.json >/dev/null 2>&1
    fi
    if echo "${selectCustomInstallType}" | grep -q ",11," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== 配置VMess+HTTPUpgrade =====================\n"
        echoContent skyBlue "\n开始配置VMess+HTTPUpgrade协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVMessHTTPUpgradePort}")
        echoContent green "\n ---> VMess_HTTPUpgrade端口：${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop
        randomPathFunction
        rm -rf "${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf" >/dev/null 2>&1
        checkPortOpen "${result[-1]}" "${domain}"
        singBoxNginxConfig "$1" "${result[-1]}"
        bootStartup nginx
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/11_VMess_HTTPUpgrade_inbounds.json
{
    "inbounds":[
        {
          "type": "vmess",
          "listen":"127.0.0.1",
          "listen_port":31306,
          "tag":"VMessHTTPUpgrade",
          "users":$(initSingBoxClients 11),
          "transport": {
            "type": "httpupgrade",
            "path": "/${currentPath}"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/11_VMess_HTTPUpgrade_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",13," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置 AnyTLS ==================\n"
        echoContent skyBlue "\n开始配置AnyTLS协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxAnyTLSPort}")
        echoContent green "\n ---> AnyTLS端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/13_anytls_inbounds.json
{
    "inbounds": [
        {
            "type": "anytls",
            "listen": "::",
            "tag":"anytls",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 13),
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/13_anytls_inbounds.json >/dev/null 2>&1
    fi

    # Socks5 入站
    if echo "${selectCustomInstallType}" | grep -q ",14,"; then
        echoContent yellow "\n================== 配置 Socks5 入站 ==================\n"
        echoContent skyBlue "\n开始配置Socks5入站端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxSocks5Port}")
        echoContent green "\n ---> Socks5端口：${result[-1]}"

        echoContent yellow "\n请输入Socks5用户名"
        read -r -p '用户名:' socks5InUser
        if [[ -z "${socks5InUser}" ]]; then
            socks5InUser="user_$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 6)"
        fi

        echoContent yellow "\n请输入Socks5密码"
        read -r -p '密码:' socks5InPass
        if [[ -z "${socks5InPass}" ]]; then
            socks5InPass="$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)"
        fi

        echoContent green "\n 用户名: ${socks5InUser}"
        echoContent green " 密码: ${socks5InPass}"

        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/14_socks5_inbounds.json
{
    "inbounds": [
        {
            "type": "socks",
            "listen": "::",
            "listen_port": ${result[-1]},
            "tag": "socks5-in",
            "users": [
                {
                    "username": "${socks5InUser}",
                    "password": "${socks5InPass}"
                }
            ]
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/14_socks5_inbounds.json >/dev/null 2>&1
    fi

    if [[ -z "$3" ]]; then
        removeSingBoxConfig wireguard_endpoints_IPv4_route
        removeSingBoxConfig wireguard_endpoints_IPv6_route
        removeSingBoxConfig wireguard_endpoints_IPv4
        removeSingBoxConfig wireguard_endpoints_IPv6

        removeSingBoxConfig IPv4_out
        removeSingBoxConfig IPv6_out
        removeSingBoxConfig IPv6_route
        removeSingBoxConfig block
        removeSingBoxConfig cn_block_outbound
        removeSingBoxConfig cn_block_route
        removeSingBoxConfig 01_direct_outbound
        removeSingBoxConfig socks5_outbound.json
        removeSingBoxConfig block_domain_outbound
        removeSingBoxConfig dns
    fi
}
# 初始化 sing-box订阅配置
initSubscribeLocalConfig() {
    rm -rf /etc/v2ray-agent/subscribe_local/sing-box/*
}
# 通用
defaultBase64Code() {
    local type=$1
    local port=$2
    local email=$3
    local id=$4
    local add=$5
    local path=$6
    local user=
    user=$(echo "${email}" | awk -F "[-]" '{print $1}')
    if [[ ! -f "/etc/v2ray-agent/subscribe_local/sing-box/${user}" ]]; then
        echo [] >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"
    fi
    local singBoxSubscribeLocalConfig=
    if [[ "${type}" == "vlesstcp" ]]; then

        echoContent yellow " ---> 通用格式(VLESS+TCP+TLS_Vision)"
        echoContent green "    vless://${id}@${currentHost}:${port}?encryption=none&security=tls&fp=chrome&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS_Vision)"
        echoContent green "协议类型:VLESS，地址:${currentHost}，端口:${port}，用户ID:${id}，安全:tls，client-fingerprint: chrome，传输方式:tcp，flow:xtls-rprx-vision，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${currentHost}:${port}?encryption=none&security=tls&type=tcp&host=${currentHost}&fp=chrome&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${currentHost}
    port: ${port}
    uuid: ${id}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"${currentHost}\",\"server_port\":${port},\"uuid\":\"${id}\",\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"packet_encoding\":\"xudp\"}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS_Vision)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentHost}%3A${port}%3Fencryption%3Dnone%26fp%3Dchrome%26security%3Dtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-vision%23${email}\n"

    elif [[ "${type}" == "vmessws" ]]; then
        qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
        qrCodeBase64Default="${qrCodeBase64Default// /}"

        echoContent yellow " ---> 通用json(VMess+WS+TLS)"
        echoContent green "    {\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
        echoContent yellow " ---> 通用vmess(VMess+WS+TLS)链接"
        echoContent green "    vmess://${qrCodeBase64Default}\n"
        echoContent yellow " ---> 二维码 vmess(VMess+WS+TLS)"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vmess://${qrCodeBase64Default}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vmess
    server: ${add}
    port: ${port}
    uuid: ${id}
    alterId: 0
    cipher: none
    udp: true
    tls: true
    client-fingerprint: chrome
    servername: ${currentHost}
    network: ws
    ws-opts:
      path: ${path}
      headers:
        Host: ${currentHost}
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vmess\",\"server\":\"${add}\",\"server_port\":${port},\"uuid\":\"${id}\",\"alter_id\":0,\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"packet_encoding\":\"packetaddr\",\"transport\":{\"type\":\"ws\",\"path\":\"${path}\",\"max_early_data\":2048,\"early_data_header_name\":\"Sec-WebSocket-Protocol\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")

        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

    elif [[ "${type}" == "vlessws" ]]; then

        echoContent yellow " ---> 通用格式(VLESS+WS+TLS)"
        echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&fp=chrome&path=${path}#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+WS+TLS)"
        echoContent green "    协议类型:VLESS，地址:${add}，伪装域名/SNI:${currentHost}，端口:${port}，client-fingerprint: chrome,用户ID:${id}，安全:tls，传输方式:ws，路径:${path}，账户名:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&fp=chrome&path=${path}#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${add}
    port: ${port}
    uuid: ${id}
    udp: true
    tls: true
    network: ws
    client-fingerprint: chrome
    servername: ${currentHost}
    ws-opts:
      path: ${path}
      headers:
        Host: ${currentHost}
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"${add}\",\"server_port\":${port},\"uuid\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"multiplex\":{\"enabled\":false,\"protocol\":\"smux\",\"max_streams\":32},\"packet_encoding\":\"xudp\",\"transport\":{\"type\":\"ws\",\"path\":\"${path}\",\"headers\":{\"Host\":\"${currentHost}\"}}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+WS+TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${currentHost}%26fp%3Dchrome%26sni%3D${currentHost}%26path%3D${path}%23${email}"

    elif
        [[ "${type}" == "vlessgrpc" ]]
    then

        echoContent yellow " ---> 通用格式(VLESS+gRPC+TLS)"
        echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&fp=chrome&serviceName=${currentPath}grpc&alpn=h2&sni=${currentHost}#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+gRPC+TLS)"
        echoContent green "    协议类型:VLESS，地址:${add}，伪装域名/SNI:${currentHost}，端口:${port}，用户ID:${id}，安全:tls，传输方式:gRPC，alpn:h2，client-fingerprint: chrome,serviceName:${currentPath}grpc，账户名:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&fp=chrome&alpn=h2&sni=${currentHost}#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${add}
    port: ${port}
    uuid: ${id}
    udp: true
    tls: true
    network: grpc
    client-fingerprint: chrome
    servername: ${currentHost}
    grpc-opts:
      grpc-service-name: ${currentPath}grpc
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\": \"vless\",\"server\": \"${add}\",\"server_port\": ${port},\"uuid\": \"${id}\",\"tls\": {  \"enabled\": true,  \"server_name\": \"${currentHost}\",  \"utls\": {    \"enabled\": true,    \"fingerprint\": \"chrome\"  }},\"packet_encoding\": \"xudp\",\"transport\": {  \"type\": \"grpc\",  \"service_name\": \"${currentPath}grpc\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+gRPC+TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${currentHost}%26serviceName%3D${currentPath}grpc%26fp%3Dchrome%26path%3D${currentPath}grpc%26sni%3D${currentHost}%26alpn%3Dh2%23${email}"

    elif [[ "${type}" == "trojan" ]]; then
        # URLEncode
        echoContent yellow " ---> Trojan(TLS)"
        echoContent green "    trojan://${id}@${currentHost}:${port}?peer=${currentHost}&fp=chrome&sni=${currentHost}&alpn=http/1.1#${currentHost}_Trojan\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${currentHost}:${port}?peer=${currentHost}&fp=chrome&sni=${currentHost}&alpn=http/1.1#${email}_Trojan
EOF

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: trojan
    server: ${currentHost}
    port: ${port}
    password: ${id}
    client-fingerprint: chrome
    udp: true
    sni: ${currentHost}
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"trojan\",\"server\":\"${currentHost}\",\"server_port\":${port},\"password\":\"${id}\",\"tls\":{\"alpn\":[\"http/1.1\"],\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 Trojan(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${currentHost}%3a${port}%3fpeer%3d${currentHost}%26fp%3Dchrome%26sni%3d${currentHost}%26alpn%3Dhttp/1.1%23${email}\n"

    elif [[ "${type}" == "trojangrpc" ]]; then
        # URLEncode

        echoContent yellow " ---> Trojan gRPC(TLS)"
        echoContent green "    trojan://${id}@${add}:${port}?encryption=none&peer=${currentHost}&fp=chrome&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${add}:${port}?encryption=none&peer=${currentHost}&security=tls&type=grpc&fp=chrome&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    server: ${add}
    port: ${port}
    type: trojan
    password: ${id}
    network: grpc
    sni: ${currentHost}
    udp: true
    grpc-opts:
      grpc-service-name: ${currentPath}trojangrpc
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"trojan\",\"server\":\"${add}\",\"server_port\":${port},\"password\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"insecure\":true,\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"transport\":{\"type\":\"grpc\",\"service_name\":\"${currentPath}trojangrpc\",\"idle_timeout\":\"15s\",\"ping_timeout\":\"15s\",\"permit_without_stream\":false},\"multiplex\":{\"enabled\":false,\"protocol\":\"smux\",\"max_streams\":32}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 Trojan gRPC(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${add}%3a${port}%3Fencryption%3Dnone%26fp%3Dchrome%26security%3Dtls%26peer%3d${currentHost}%26type%3Dgrpc%26sni%3d${currentHost}%26path%3D${currentPath}trojangrpc%26alpn%3Dh2%26serviceName%3D${currentPath}trojangrpc%23${email}\n"

    elif [[ "${type}" == "hysteria" ]]; then
        echoContent yellow " ---> Hysteria(TLS)"
        local clashMetaPortContent="port: ${port}"
        local multiPort=
        local multiPortEncode
        if echo "${port}" | grep -q "-"; then
            clashMetaPortContent="ports: ${port}"
            multiPort="mport=${port}&"
            multiPortEncode="mport%3D${port}%26"
        fi

        echoContent green "    hysteria2://${id}@${currentHost}:${singBoxHysteria2Port}?${multiPort}peer=${currentHost}&insecure=0&sni=${currentHost}&alpn=h3#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
hysteria2://${id}@${currentHost}:${singBoxHysteria2Port}?${multiPort}peer=${currentHost}&insecure=0&sni=${currentHost}&alpn=h3#${email}
EOF
        echoContent yellow " ---> v2rayN(hysteria+TLS)"
        echo "{\"server\": \"${currentHost}:${port}\",\"socks5\": { \"listen\": \"127.0.0.1:7798\", \"timeout\": 300},\"auth\":\"${id}\",\"tls\":{\"sni\":\"${currentHost}\"}}" | jq

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: hysteria2
    server: ${currentHost}
    ${clashMetaPortContent}
    password: ${id}
    alpn:
        - h3
    sni: ${currentHost}
    up: "${hysteria2ClientUploadSpeed} Mbps"
    down: "${hysteria2ClientDownloadSpeed} Mbps"
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"hysteria2\",\"server\":\"${currentHost}\",\"server_port\":${singBoxHysteria2Port},\"up_mbps\":${hysteria2ClientUploadSpeed},\"down_mbps\":${hysteria2ClientDownloadSpeed},\"password\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"alpn\":[\"h3\"]}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 Hysteria2(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=hysteria2%3A%2F%2F${id}%40${currentHost}%3A${singBoxHysteria2Port}%3F${multiPortEncode}peer%3D${currentHost}%26insecure%3D0%26sni%3D${currentHost}%26alpn%3Dh3%23${email}\n"

    elif [[ "${type}" == "vlessReality" ]]; then
        local realityServerName=${singBoxVLESSRealityVisionServerName}
        local publicKey=${singBoxVLESSRealityPublicKey}
        local realityMldsa65Verify=${currentRealityMldsa65Verify}
        echoContent yellow " ---> 通用格式(VLESS+reality+uTLS+Vision)"
        echoContent green "    vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&pqv=${realityMldsa65Verify}&type=tcp&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+reality+uTLS+Vision)"
        echoContent green "协议类型:VLESS reality，地址:$(getPublicIP)，publicKey:${publicKey}，shortId: 6ba85179e30d4fc2，pqv=${realityMldsa65Verify}，serverNames：${realityServerName}，端口:${port}，用户ID:${id}，传输方式:tcp，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&pqv=${realityMldsa65Verify}&type=tcp&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: $(getPublicIP)
    port: ${port}
    uuid: ${id}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${realityServerName}
    reality-opts:
      public-key: ${publicKey}
      short-id: 6ba85179e30d4fc2
    client-fingerprint: chrome
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"$(getPublicIP)\",\"server_port\":${port},\"uuid\":\"${id}\",\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"${realityServerName}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,\"public_key\":\"${publicKey}\",\"short_id\":\"6ba85179e30d4fc2\"}},\"packet_encoding\":\"xudp\"}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+reality+uTLS+Vision)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${port}%3Fencryption%3Dnone%26security%3Dreality%26type%3Dtcp%26sni%3D${realityServerName}%26fp%3Dchrome%26pbk%3D${publicKey}%26sid%3D6ba85179e30d4fc2%26flow%3Dxtls-rprx-vision%23${email}\n"

    elif [[ "${type}" == "vlessRealityGRPC" ]]; then
        local realityServerName=${singBoxVLESSRealityGRPCServerName}
        local publicKey=${singBoxVLESSRealityPublicKey}
        local realityMldsa65Verify=${currentRealityMldsa65Verify}

        echoContent yellow " ---> 通用格式(VLESS+reality+uTLS+gRPC)"
        # pqv=${realityMldsa65Verify}&
        echoContent green "    vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=grpc&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&path=grpc&serviceName=grpc#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+reality+uTLS+gRPC)"
        # pqv=${realityMldsa65Verify}，
        echoContent green "协议类型:VLESS reality，serviceName:grpc，地址:$(getPublicIP)，publicKey:${publicKey}，shortId: 6ba85179e30d4fc2，serverNames：${realityServerName}，端口:${port}，用户ID:${id}，传输方式:gRPC，client-fingerprint：chrome，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&pqv=${realityMldsa65Verify}&type=grpc&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&path=grpc&serviceName=grpc#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: $(getPublicIP)
    port: ${port}
    uuid: ${id}
    network: grpc
    tls: true
    udp: true
    servername: ${realityServerName}
    reality-opts:
      public-key: ${publicKey}
      short-id: 6ba85179e30d4fc2
    grpc-opts:
      grpc-service-name: "grpc"
    client-fingerprint: chrome
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"$(getPublicIP)\",\"server_port\":${port},\"uuid\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${realityServerName}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,\"public_key\":\"${publicKey}\",\"short_id\":\"6ba85179e30d4fc2\"}},\"packet_encoding\":\"xudp\",\"transport\":{\"type\":\"grpc\",\"service_name\":\"grpc\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+reality+uTLS+gRPC)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${port}%3Fencryption%3Dnone%26security%3Dreality%26type%3Dgrpc%26sni%3D${realityServerName}%26fp%3Dchrome%26pbk%3D${publicKey}%26sid%3D6ba85179e30d4fc2%26path%3Dgrpc%26serviceName%3Dgrpc%23${email}\n"
    elif [[ "${type}" == "tuic" ]]; then
        local tuicUUID=
        tuicUUID=$(echo "${id}" | awk -F "[_]" '{print $1}')

        local tuicPassword=
        tuicPassword=$(echo "${id}" | awk -F "[_]" '{print $2}')

        if [[ -z "${email}" ]]; then
            echoContent red " ---> 读取配置失败，请重新安装"
            exit 0
        fi

        echoContent yellow " ---> 格式化明文(Tuic+TLS)"
        echoContent green "    协议类型:Tuic，地址:${currentHost}，端口：${port}，uuid：${tuicUUID}，password：${tuicPassword}，congestion-controller:${tuicAlgorithm}，alpn: h3，账户名:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
tuic://${tuicUUID}:${tuicPassword}@${currentHost}:${port}?congestion_control=${tuicAlgorithm}&alpn=h3&sni=${currentHost}&udp_relay_mode=quic&allow_insecure=0#${email}
EOF
        echoContent yellow " ---> v2rayN(Tuic+TLS)"
        echo "{\"relay\": {\"server\": \"${currentHost}:${port}\",\"uuid\": \"${tuicUUID}\",\"password\": \"${tuicPassword}\",\"ip\": \"${currentHost}\",\"congestion_control\": \"${tuicAlgorithm}\",\"alpn\": [\"h3\"]},\"local\": {\"server\": \"127.0.0.1:7798\"},\"log_level\": \"warn\"}" | jq

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    server: ${currentHost}
    type: tuic
    port: ${port}
    uuid: ${tuicUUID}
    password: ${tuicPassword}
    alpn:
     - h3
    congestion-controller: ${tuicAlgorithm}
    disable-sni: true
    reduce-rtt: true
    sni: ${email}
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\": \"tuic\",\"server\": \"${currentHost}\",\"server_port\": ${port},\"uuid\": \"${tuicUUID}\",\"password\": \"${tuicPassword}\",\"congestion_control\": \"${tuicAlgorithm}\",\"tls\": {\"enabled\": true,\"server_name\": \"${currentHost}\",\"alpn\": [\"h3\"]}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow "\n ---> 二维码 Tuic"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=tuic%3A%2F%2F${tuicUUID}%3A${tuicPassword}%40${currentHost}%3A${tuicPort}%3Fcongestion_control%3D${tuicAlgorithm}%26alpn%3Dh3%26sni%3D${currentHost}%26udp_relay_mode%3Dquic%26allow_insecure%3D0%23${email}\n"
    elif [[ "${type}" == "naive" ]]; then
        echoContent yellow " ---> Naive(TLS)"

        echoContent green "    naive+https://${email}:${id}@${currentHost}:${port}?padding=true#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
naive+https://${email}:${id}@${currentHost}:${port}?padding=true#${email}
EOF
        echoContent yellow " ---> 二维码 Naive(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=naive%2Bhttps%3A%2F%2F${email}%3A${id}%40${currentHost}%3A${port}%3Fpadding%3Dtrue%23${email}\n"
    elif [[ "${type}" == "vmessHTTPUpgrade" ]]; then
        qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"httpupgrade\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
        qrCodeBase64Default="${qrCodeBase64Default// /}"

        echoContent yellow " ---> 通用json(VMess+HTTPUpgrade+TLS)"
        echoContent green "    {\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"httpupgrade\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
        echoContent yellow " ---> 通用vmess(VMess+HTTPUpgrade+TLS)链接"
        echoContent green "    vmess://${qrCodeBase64Default}\n"
        echoContent yellow " ---> 二维码 vmess(VMess+HTTPUpgrade+TLS)"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
   vmess://${qrCodeBase64Default}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vmess
    server: ${add}
    port: ${port}
    uuid: ${id}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    client-fingerprint: chrome
    servername: ${currentHost}
    network: ws
    ws-opts:
     path: ${path}
     headers:
       Host: ${currentHost}
     v2ray-http-upgrade: true
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vmess\",\"server\":\"${add}\",\"server_port\":${port},\"uuid\":\"${id}\",\"security\":\"auto\",\"alter_id\":0,\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"packet_encoding\":\"packetaddr\",\"transport\":{\"type\":\"httpupgrade\",\"path\":\"${path}\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")

        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

    elif [[ "${type}" == "anytls" ]]; then
        echoContent yellow " ---> AnyTLS"

        echoContent yellow " ---> 格式化明文(AnyTLS)"
        echoContent green "协议类型:anytls，地址:${currentHost}，端口:${singBoxAnyTLSPort}，用户ID:${id}，传输方式:tcp，账户名:${email}\n"

        echoContent green "    anytls://${id}@${currentHost}:${singBoxAnyTLSPort}?peer=${currentHost}&insecure=0&sni=${currentHost}#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
anytls://${id}@${currentHost}:${singBoxAnyTLSPort}?peer=${currentHost}&insecure=0&sni=${currentHost}#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: anytls
    port: ${singBoxAnyTLSPort}
    server: ${currentHost}
    password: ${id}
    client-fingerprint: chrome
    udp: true
    sni: ${currentHost}
    alpn:
      - h2
      - http/1.1
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"anytls\",\"server\":\"${currentHost}\",\"server_port\":${singBoxAnyTLSPort},\"password\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 AnyTLS"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=anytls%3A%2F%2F${id}%40${currentHost}%3A${singBoxAnyTLSPort}%3Fpeer%3D${currentHost}%26insecure%3D0%26sni%3D${currentHost}%23${email}\n"
    fi

}

# 账号
showAccounts() {
    readInstallType
    readInstallProtocolType
    readConfigHostPathUUID
    readSingBoxConfig

    echo
    echoContent skyBlue "\n进度 $1/${totalProgress} : 账号"

    initSubscribeLocalConfig
    # VLESS TCP
    if echo ${currentInstallProtocolType} | grep -q ",0,"; then

        echoContent skyBlue "============================= VLESS TCP TLS_Vision [推荐] ==============================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            echoContent skyBlue "\n ---> 账号:${email}"
            echo
            defaultBase64Code vlesstcp "${currentDefaultPort}${singBoxVLESSVisionPort}" "${email}" "$(echo "${user}" | jq -r .id//.uuid)"
        done
    fi

    # VLESS WS
    if echo ${currentInstallProtocolType} | grep -q ",1,"; then
        echoContent skyBlue "\n================================ VLESS WS TLS [仅CDN推荐] ================================\n"

        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            local vlessWSPort="${singBoxVLESSWSPort}"
            echo
            local path="${singBoxVLESSWSPath}"

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessws "${vlessWSPort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                    echo
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi
    # trojan grpc
    if echo ${currentInstallProtocolType} | grep -q ",2,"; then
        echoContent skyBlue "\n================================  Trojan gRPC TLS [仅CDN推荐]  ================================\n"
        jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)
            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code trojangrpc "${currentDefaultPort}" "${email}${count}" "$(echo "${user}" | jq -r .password)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')

        done
    fi
    # VMess WS
    if echo ${currentInstallProtocolType} | grep -q ",3,"; then
        echoContent skyBlue "\n================================ VMess WS TLS [仅CDN推荐]  ================================\n"
        local path="${singBoxVMessWSPath}"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            local vmessPort="${singBoxVMessWSPort}"

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vmessws "${vmessPort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi

    # trojan tcp
    if echo ${currentInstallProtocolType} | grep -q ",4,"; then
        echoContent skyBlue "\n==================================  Trojan TLS [不推荐] ==================================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)
            echoContent skyBlue "\n ---> 账号:${email}"

            defaultBase64Code trojan "${currentDefaultPort}${singBoxTrojanPort}" "${email}" "$(echo "${user}" | jq -r .password)"
        done
    fi
    # VLESS grpc
    if echo ${currentInstallProtocolType} | grep -q ",5,"; then
        echoContent skyBlue "\n=============================== VLESS gRPC TLS [仅CDN推荐]  ===============================\n"
        jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do

            local email=
            email=$(echo "${user}" | jq -r .email)

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessgrpc "${currentDefaultPort}" "${email}${count}" "$(echo "${user}" | jq -r .id)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')

        done
    fi
    # hysteria2
    if echo ${currentInstallProtocolType} | grep -q ",6," || [[ -n "${hysteriaPort}" ]]; then
        readPortHopping "hysteria2" "${singBoxHysteria2Port}"
        echoContent skyBlue "\n================================  Hysteria2 TLS [推荐] ================================\n"
        local hysteria2DefaultPort=
        if [[ -n "${hysteria2PortHoppingStart}" && -n "${hysteria2PortHoppingEnd}" ]]; then
            hysteria2DefaultPort="${hysteria2PortHopping}"
        else
            hysteria2DefaultPort=${singBoxHysteria2Port}
        fi

        jq -r -c '.inbounds[]|.users[]' "${configPath}06_hysteria2_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code hysteria "${hysteria2DefaultPort}" "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .password)"
        done

    fi

    # VLESS reality vision
    if echo ${currentInstallProtocolType} | grep -q ",7,"; then
        echoContent skyBlue "============================= VLESS reality_vision [推荐]  ==============================\n"
        jq .inbounds[1].settings.clients//.inbounds[0].users ${configPath}07_VLESS_vision_reality_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            echoContent skyBlue "\n ---> 账号:${email}"
            echo
            defaultBase64Code vlessReality "${singBoxVLESSRealityVisionPort}" "${email}" "$(echo "${user}" | jq -r .id//.uuid)"
        done
    fi
    # VLESS reality gRPC
    if echo ${currentInstallProtocolType} | grep -q ",8,"; then
        echoContent skyBlue "============================== VLESS reality_gRPC [推荐] ===============================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}08_VLESS_vision_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            echoContent skyBlue "\n ---> 账号:${email}"
            echo
            defaultBase64Code vlessRealityGRPC "${singBoxVLESSRealityGRPCPort}" "${email}" "$(echo "${user}" | jq -r .id//.uuid)"
        done
    fi
    # tuic
    if echo ${currentInstallProtocolType} | grep -q ",9," || [[ -n "${tuicPort}" ]]; then
        echoContent skyBlue "\n================================  Tuic TLS [推荐]  ================================\n"
        jq -r -c '.inbounds[].users[]' "${configPath}09_tuic_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code tuic "${singBoxTuicPort}" "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .uuid)_$(echo "${user}" | jq -r .password)"
        done

    fi
    # naive
    if echo ${currentInstallProtocolType} | grep -q ",10," || [[ -n "${singBoxNaivePort}" ]]; then
        echoContent skyBlue "\n================================  naive TLS [推荐，不支持ClashMeta]  ================================\n"

        jq -r -c '.inbounds[]|.users[]' "${configPath}10_naive_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .username)"
            echo
            defaultBase64Code naive "${singBoxNaivePort}" "$(echo "${user}" | jq -r .username)" "$(echo "${user}" | jq -r .password)"
        done

    fi
    # VMess HTTPUpgrade
    if echo ${currentInstallProtocolType} | grep -q ",11,"; then
        echoContent skyBlue "\n================================ VMess HTTPUpgrade TLS [仅CDN推荐]  ================================\n"
        local path="${singBoxVMessHTTPUpgradePath}"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}11_VMess_HTTPUpgrade_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            local vmessHTTPUpgradePort="${singBoxVMessHTTPUpgradePort}"

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vmessHTTPUpgrade "${vmessHTTPUpgradePort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi
    # AnyTLS
    if echo ${currentInstallProtocolType} | grep -q ",13,"; then
        echoContent skyBlue "\n================================  AnyTLS ================================\n"

        jq -r -c '.inbounds[]|.users[]' "${configPath}13_anytls_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code anytls "${singBoxAnyTLSPort}" "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .password)"
        done

    fi
}
# 移除nginx302配置
removeNginx302() {
    local count=
    grep -n "return 302" <"${nginxConfigPath}alone.conf" | while read -r line; do

        if ! echo "${line}" | grep -q "request_uri"; then
            local removeIndex=
            removeIndex=$(echo "${line}" | awk -F "[:]" '{print $1}')
            removeIndex=$((removeIndex + count))
            sed -i "${removeIndex}d" ${nginxConfigPath}alone.conf
            count=$((count - 1))
        fi
    done
}

# 检查302是否成功
checkNginx302() {
    local domain302Status=
    domain302Status=$(curl -s "https://${currentHost}:${currentPort}")
    if echo "${domain302Status}" | grep -q "302"; then
        #        local domain302Result=
        #        domain302Result=$(curl -L -s "https://${currentHost}:${currentPort}")
        #        if [[ -n "${domain302Result}" ]]; then
        echoContent green " ---> 302重定向设置完毕"
        exit 0
        #        fi
    fi
    echoContent red " ---> 302重定向设置失败，请仔细检查是否和示例相同"
    backupNginxConfig restoreBackup
}

# 备份恢复nginx文件
backupNginxConfig() {
    if [[ "$1" == "backup" ]]; then
        cp ${nginxConfigPath}alone.conf /etc/v2ray-agent/alone_backup.conf
        echoContent green " ---> nginx配置文件备份成功"
    fi

    if [[ "$1" == "restoreBackup" ]] && [[ -f "/etc/v2ray-agent/alone_backup.conf" ]]; then
        cp /etc/v2ray-agent/alone_backup.conf ${nginxConfigPath}alone.conf
        echoContent green " ---> nginx配置文件恢复备份成功"
        rm /etc/v2ray-agent/alone_backup.conf
    fi

}
# 添加302配置
addNginx302() {

    local count=1
    grep -n "location / {" <"${nginxConfigPath}alone.conf" | while read -r line; do
        if [[ -n "${line}" ]]; then
            local insertIndex=
            insertIndex="$(echo "${line}" | awk -F "[:]" '{print $1}')"
            insertIndex=$((insertIndex + count))
            sed "${insertIndex}i return 302 '$1';" ${nginxConfigPath}alone.conf >${nginxConfigPath}tmpfile && mv ${nginxConfigPath}tmpfile ${nginxConfigPath}alone.conf
            count=$((count + 1))
        else
            echoContent red " ---> 302添加失败"
            backupNginxConfig restoreBackup
        fi

    done
}

# 卸载脚本
unInstall() {
    read -r -p "是否确认卸载安装内容？[y/n]:" unInstallStatus
    if [[ "${unInstallStatus}" != "y" ]]; then
        echoContent green " ---> 放弃卸载"
        menu
        exit 0
    fi
    checkBTPanel
    echoContent yellow " ---> 脚本不会删除acme相关配置，删除请手动执行 [rm -rf /root/.acme.sh]"
    handleNginx stop
    if [[ -z $(pgrep -f "nginx") ]]; then
        echoContent green " ---> 停止Nginx成功"
    fi
    if [[ "${release}" == "alpine" ]]; then
        handleSingBox stop
        rc-update del sing-box default
        rm -rf /etc/init.d/sing-box
        echoContent green " ---> 删除sing-box开机自启完成"
    else
        handleSingBox stop
        rm -rf /etc/systemd/system/sing-box.service
        echoContent green " ---> 删除sing-box开机自启完成"
    fi

    rm -rf /etc/v2ray-agent
    rm -rf ${nginxConfigPath}alone.conf
    rm -rf ${nginxConfigPath}checkPortOpen.conf >/dev/null 2>&1
    rm -rf "${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf" >/dev/null 2>&1
    rm -rf ${nginxConfigPath}checkPortOpen.conf >/dev/null 2>&1

    unInstallSubscribe

    if [[ -d "${nginxStaticPath}" && -f "${nginxStaticPath}/check" ]]; then
        rm -rf "${nginxStaticPath}"
        echoContent green " ---> 删除伪装网站完成"
    fi

    rm -rf /usr/bin/vasma
    rm -rf /usr/sbin/vasma
    echoContent green " ---> 卸载快捷方式完成"
    echoContent green " ---> 卸载v2ray-agent脚本完成"
}

# CDN节点管理
manageCDN() {
    echoContent skyBlue "\n进度 $1/1 : CDN节点管理"
    local setCDNDomain=

    if echo "${currentInstallProtocolType}" | grep -qE ",1,|,2,|,3,|,5,|,11,"; then
        echoContent red "=============================================================="
        echoContent yellow "# 注意事项"
        echoContent yellow "\n教程地址:"
        echoContent skyBlue "https://www.v2ray-agent.com/archives/cloudflarezi-xuan-ip"
        echoContent red "\n如对Cloudflare优化不了解，请不要使用"

        echoContent yellow "1.CNAME www.digitalocean.com"
        echoContent yellow "2.CNAME who.int"
        echoContent yellow "3.CNAME blog.hostmonit.com"
        echoContent yellow "4.CNAME www.visa.com.hk"
        echoContent yellow "5.手动输入[可输入多个，比如: 1.1.1.1,1.1.2.2,cloudflare.com 逗号分隔]"
        echoContent yellow "6.移除CDN节点"
        echoContent red "=============================================================="
        read -r -p "请选择:" selectCDNType
        case ${selectCDNType} in
        1)
            setCDNDomain="www.digitalocean.com"
            ;;
        2)
            setCDNDomain="who.int"
            ;;
        3)
            setCDNDomain="blog.hostmonit.com"
            ;;
        4)
            setCDNDomain="www.visa.com.hk"
            ;;
        5)
            read -r -p "请输入想要自定义CDN IP或者域名:" setCDNDomain
            ;;
        6)
            echo >/etc/v2ray-agent/cdn
            echoContent green " ---> 移除成功"
            exit 0
            ;;
        esac

        if [[ -n "${setCDNDomain}" ]]; then
            echo >/etc/v2ray-agent/cdn
            echo "${setCDNDomain}" >"/etc/v2ray-agent/cdn"
            echoContent green " ---> 修改CDN成功"
            subscribe false false
        else
            echoContent red " ---> 不可以为空，请重新输入"
            manageCDN 1
        fi
    else
        echoContent yellow "\n教程地址:"
        echoContent skyBlue "https://www.v2ray-agent.com/archives/cloudflarezi-xuan-ip\n"
        echoContent red " ---> 未检测到可以使用的协议，仅支持ws、grpc、HTTPUpgrade相关的协议"
    fi
}
# 自定义uuid
customUUID() {
    read -r -p "请输入合法的UUID，[回车]随机UUID:" currentCustomUUID
    echo
    if [[ -z "${currentCustomUUID}" ]]; then
        currentCustomUUID=$(${ctlPath} generate uuid)
        echoContent yellow "uuid：${currentCustomUUID}\n"
    else
        local checkUUID=
        checkUUID=$(jq -r --arg currentUUID "$currentCustomUUID" ".inbounds[0].users[] | select(.uuid == \$currentUUID) | .name//.username" ${configPath}${frontingType}.json)
        if [[ -n "${checkUUID}" ]]; then
            echoContent red " ---> UUID不可重复"
            exit 0
        fi
    fi
}

# 自定义email
customUserEmail() {
    read -r -p "请输入合法的email，[回车]随机email:" currentCustomEmail
    echo
    if [[ -z "${currentCustomEmail}" ]]; then
        currentCustomEmail="${currentCustomUUID}"
        echoContent yellow "email: ${currentCustomEmail}\n"
    else
        local checkEmail=
        checkEmail=$(jq -r --arg currentEmail "$currentCustomEmail" ".inbounds[0].users[] | select(.name == \$currentEmail) | .name" ${configPath}${frontingType}.json)
        if [[ -n "${checkEmail}" ]]; then
            echoContent red " ---> email不可重复"
            exit 0
        fi
    fi
}

# 添加用户
addUser() {
    read -r -p "请输入要添加的用户数量:" userNum
    echo
    if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
        echoContent red " ---> 输入有误，请重新输入"
        exit 0
    fi
    local userConfig=".inbounds[0].users"

    while [[ ${userNum} -gt 0 ]]; do
        readConfigHostPathUUID
        local users=
        ((userNum--)) || true

        customUUID
        customUserEmail

        uuid=${currentCustomUUID}
        email=${currentCustomEmail}

        # VLESS TCP
        if echo "${currentInstallProtocolType}" | grep -q ",0,"; then
            local clients=
            clients=$(initSingBoxClients 0 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}02_VLESS_TCP_inbounds.json)
            echo "${clients}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
        fi

        # VLESS WS
        if echo "${currentInstallProtocolType}" | grep -q ",1,"; then
            local clients=
            clients=$(initSingBoxClients 1 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}03_VLESS_WS_inbounds.json)
            echo "${clients}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        # trojan grpc
        if echo "${currentInstallProtocolType}" | grep -q ",2,"; then
            local clients=
            clients=$(initSingBoxClients 2 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi
        # VMess WS
        if echo "${currentInstallProtocolType}" | grep -q ",3,"; then
            local clients=
            clients=$(initSingBoxClients 3 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}05_VMess_WS_inbounds.json)
            echo "${clients}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi
        # trojan tcp
        if echo "${currentInstallProtocolType}" | grep -q ",4,"; then
            local clients=
            clients=$(initSingBoxClients 4 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}04_trojan_TCP_inbounds.json)
            echo "${clients}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi

        # vless grpc
        if echo "${currentInstallProtocolType}" | grep -q ",5,"; then
            local clients=
            clients=$(initSingBoxClients 5 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}06_VLESS_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        # vless reality vision
        if echo "${currentInstallProtocolType}" | grep -q ",7,"; then
            local clients=
            local realityUserConfig=".inbounds[0].users"
            clients=$(initSingBoxClients 7 "${uuid}" "${email}")
            clients=$(jq -r "${realityUserConfig} = ${clients}" ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${clients}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi

        # vless reality grpc
        if echo "${currentInstallProtocolType}" | grep -q ",8,"; then
            local clients=
            clients=$(initSingBoxClients 8 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}08_VLESS_vision_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}08_VLESS_vision_gRPC_inbounds.json
        fi

        # hysteria2
        if echo ${currentInstallProtocolType} | grep -q ",6,"; then
            local clients=
            clients=$(initSingBoxClients 6 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}06_hysteria2_inbounds.json")
            echo "${clients}" | jq . >"${singBoxConfigPath}06_hysteria2_inbounds.json"
        fi

        # tuic
        if echo ${currentInstallProtocolType} | grep -q ",9,"; then
            local clients=
            clients=$(initSingBoxClients 9 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}09_tuic_inbounds.json")
            echo "${clients}" | jq . >"${singBoxConfigPath}09_tuic_inbounds.json"
        fi
        # naive
        if echo ${currentInstallProtocolType} | grep -q ",10,"; then
            local clients=
            clients=$(initSingBoxClients 10 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}10_naive_inbounds.json")
            echo "${clients}" | jq . >"${singBoxConfigPath}10_naive_inbounds.json"
        fi
        # VMess WS
        if echo "${currentInstallProtocolType}" | grep -q ",11,"; then
            local clients=
            clients=$(initSingBoxClients 11 "${uuid}" "${email}")
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}11_VMess_HTTPUpgrade_inbounds.json)
            echo "${clients}" | jq . >${configPath}11_VMess_HTTPUpgrade_inbounds.json
        fi
        # anytls
        if echo "${currentInstallProtocolType}" | grep -q ",13,"; then
            local clients=
            clients=$(initSingBoxClients 13 "${uuid}" "${email}")

            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}13_anytls_inbounds.json)
            echo "${clients}" | jq . >${configPath}13_anytls_inbounds.json
        fi
    done
    reloadCore
    echoContent green " ---> 添加完成"
    readNginxSubscribe
    if [[ -n "${subscribePort}" ]]; then
        subscribe false
    fi
    manageAccount 1
}
# 移除用户
removeUser() {
    local uuid=
    jq -r -c .inbounds[0].users[].name//.inbounds[0].users[].username ${configPath}${frontingType:-$frontingTypeReality}.json | awk '{print NR""":"$0}'
    read -r -p "请选择要删除的用户编号[仅支持单个删除]:" delUserIndex
    if [[ $(jq -r '.inbounds[0].users|length' ${configPath}${frontingType:-$frontingTypeReality}.json) -lt ${delUserIndex} ]]; then
        echoContent red " ---> 选择错误"
    else
        delUserIndex=$((delUserIndex - 1))
    fi

    if [[ -n "${delUserIndex}" ]]; then

        if echo ${currentInstallProtocolType} | grep -q ",0,"; then
            local vlessVision
            vlessVision=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}02_VLESS_TCP_inbounds.json)
            echo "${vlessVision}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
        fi
        if echo ${currentInstallProtocolType} | grep -q ",1,"; then
            local vlessWSResult
            vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])//.inbounds[0].users['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
            echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",2,"; then
            local trojangRPCUsers
            trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])//.inbounds[0].users['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",3,"; then
            local vmessWSResult
            vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
            echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",5,"; then
            local vlessGRPCResult
            vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
            echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",4,"; then
            local trojanTCPResult
            trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
            echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",7,"; then
            local vlessRealityResult
            vlessRealityResult=$(jq -r 'del(.inbounds[1].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${vlessRealityResult}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi
        if echo ${currentInstallProtocolType} | grep -q ",8,"; then
            local vlessRealityGRPCResult
            vlessRealityGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}08_VLESS_vision_gRPC_inbounds.json)
            echo "${vlessRealityGRPCResult}" | jq . >${configPath}08_VLESS_vision_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",6,"; then
            local hysteriaResult
            hysteriaResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}06_hysteria2_inbounds.json")
            echo "${hysteriaResult}" | jq . >"${singBoxConfigPath}06_hysteria2_inbounds.json"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",9,"; then
            local tuicResult
            tuicResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}09_tuic_inbounds.json")
            echo "${tuicResult}" | jq . >"${singBoxConfigPath}09_tuic_inbounds.json"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",10,"; then
            local naiveResult
            naiveResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}10_naive_inbounds.json")
            echo "${naiveResult}" | jq . >"${singBoxConfigPath}10_naive_inbounds.json"
        fi
        # VMess HTTPUpgrade
        if echo ${currentInstallProtocolType} | grep -q ",11,"; then
            local vmessHTTPUpgradeResult
            vmessHTTPUpgradeResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json")
            echo "${vmessHTTPUpgradeResult}" | jq . >"${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json"
            echo "${vmessHTTPUpgradeResult}" | jq . >${configPath}11_VMess_HTTPUpgrade_inbounds.json
        fi
        reloadCore
        readNginxSubscribe
        if [[ -n "${subscribePort}" ]]; then
            subscribe false
        fi
    fi
    manageAccount 1
}
# 更新脚本
updateV2RayAgent() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 更新v2ray-agent脚本"
    rm -rf /etc/v2ray-agent/install.sh
    if [[ "${release}" == "alpine" ]]; then
        wget -c -q -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    else
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    fi

    sudo chmod 700 /etc/v2ray-agent/install.sh
    local version
    version=$(grep '当前版本：v' "/etc/v2ray-agent/install.sh" | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')

    echoContent green "\n ---> 更新完毕"
    echoContent yellow " ---> 请手动执行[vasma]打开脚本"
    echoContent green " ---> 当前版本：${version}\n"
    echoContent yellow "如更新不成功，请手动执行下面命令\n"
    echoContent skyBlue "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
    echo
    exit 0
}

# 防火墙
handleFirewall() {
    if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
        systemctl stop ufw >/dev/null 2>&1
        systemctl disable ufw >/dev/null 2>&1
        echoContent green " ---> ufw关闭成功"

    fi

    if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
        systemctl stop firewalld >/dev/null 2>&1
        systemctl disable firewalld >/dev/null 2>&1
        echoContent green " ---> firewalld关闭成功"
    fi
}

# 安装BBR
bbrInstall() {
    echoContent red "\n=============================================================="
    echoContent green "BBR、DD脚本用的[ylx2016]的成熟作品，地址[https://github.com/ylx2016/Linux-NetSpeed]，请熟知"
    echoContent yellow "1.安装脚本【推荐原版BBR+FQ】"
    echoContent yellow "2.回退主目录"
    echoContent red "=============================================================="
    read -r -p "请选择:" installBBRStatus
    if [[ "${installBBRStatus}" == "1" ]]; then
        wget -O tcpx.sh "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
    else
        menu
    fi
}

# 脚本快捷方式
aliasInstall() {

    if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <"$HOME/install.sh" -q "作者:mack-a"; then
        mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
        local vasmaType=
        if [[ -d "/usr/bin/" ]]; then
            if [[ ! -f "/usr/bin/vasma" ]]; then
                ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
                chmod 700 /usr/bin/vasma
                vasmaType=true
            fi

            rm -rf "$HOME/install.sh"
        elif [[ -d "/usr/sbin" ]]; then
            if [[ ! -f "/usr/sbin/vasma" ]]; then
                ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
                chmod 700 /usr/sbin/vasma
                vasmaType=true
            fi
            rm -rf "$HOME/install.sh"
        fi
        if [[ "${vasmaType}" == "true" ]]; then
            echoContent green "快捷方式创建成功，可执行[vasma]重新打开脚本"
        fi
    fi
}

# 检查ipv6、ipv4
checkIPv6() {
    currentIPv6IP=$(curl -s -6 -m 4 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)

    if [[ -z "${currentIPv6IP}" ]]; then
        echoContent red " ---> 不支持ipv6"
        exit 0
    fi
}

# ipv6 分流
ipv6Routing() {
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> 未安装，请使用脚本安装"
        menu
        exit 0
    fi

    checkIPv6
    echoContent skyBlue "\n功能 1/${totalProgress} : IPv6分流"
    echoContent red "\n=============================================================="
    echoContent yellow "1.查看已分流域名"
    echoContent yellow "2.添加域名"
    echoContent yellow "3.设置IPv6全局"
    echoContent yellow "4.卸载IPv6分流"
    echoContent red "=============================================================="
    read -r -p "请选择:" ipv6Status
    if [[ "${ipv6Status}" == "1" ]]; then
        showIPv6Routing
        exit 0
    elif [[ "${ipv6Status}" == "2" ]]; then
        echoContent red "=============================================================="
        echoContent yellow "# 注意事项\n"
        echoContent yellow "# 注意事项"
        echoContent yellow "# 使用教程：https://www.v2ray-agent.com/archives/1683226921000 \n"

        read -r -p "请按照上面示例录入域名:" domainList
        if [[ -n "${singBoxConfigPath}" ]]; then
            addSingBoxRouteRule "IPv6_out" "${domainList}" "IPv6_route"
            addSingBoxOutbound 01_direct_outbound
            addSingBoxOutbound IPv6_out
            addSingBoxOutbound IPv4_out
        fi

        echoContent green " ---> 添加完毕"

    elif [[ "${ipv6Status}" == "3" ]]; then

        echoContent red "=============================================================="
        echoContent yellow "# 注意事项\n"
        echoContent yellow "1.会删除所有设置的分流规则"
        echoContent yellow "2.会删除IPv6之外的所有出站规则\n"
        read -r -p "是否确认设置？[y/n]:" IPv6OutStatus

        if [[ "${IPv6OutStatus}" == "y" ]]; then
            if [[ -n "${singBoxConfigPath}" ]]; then

                removeSingBoxConfig IPv4_out

                removeSingBoxConfig wireguard_endpoints_IPv4_route
                removeSingBoxConfig wireguard_endpoints_IPv6_route
                removeSingBoxConfig wireguard_endpoints_IPv4
                removeSingBoxConfig wireguard_endpoints_IPv6

                removeSingBoxConfig socks5_02_inbound_route

                removeSingBoxConfig IPv6_route

                removeSingBoxConfig 01_direct_outbound

                addSingBoxOutbound IPv6_out

            fi

            echoContent green " ---> IPv6全局出站设置完毕"
        else

            echoContent green " ---> 放弃设置"
            exit 0
        fi

    elif [[ "${ipv6Status}" == "4" ]]; then
        if [[ -n "${singBoxConfigPath}" ]]; then
            removeSingBoxConfig IPv6_out
            removeSingBoxConfig "IPv6_route"
            addSingBoxOutbound "01_direct_outbound"
        fi

        echoContent green " ---> IPv6分流卸载成功"
    else
        echoContent red " ---> 选择错误"
        exit 0
    fi

    reloadCore
}

# ipv6分流规则展示
showIPv6Routing() {
    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ -f "${singBoxConfigPath}IPv6_route.json" ]]; then
            echoContent yellow "sing-box"
            jq -r -c '.route.rules[]|select (.outbound=="IPv6_out")' "${singBoxConfigPath}IPv6_route.json" | jq -r
        elif [[ ! -f "${singBoxConfigPath}IPv6_route.json" && -f "${singBoxConfigPath}IPv6_out.json" ]]; then
            echoContent yellow "sing-box"
            echoContent green " ---> 已设置IPv6全局分流"
        else
            echoContent yellow " ---> 未安装IPv6分流"
        fi
    fi
}

# 根据tag卸载Routing
unInstallRouting() {
    local tag=$1
    local type=$2
    local protocol=$3

    if [[ -f "${configPath}09_routing.json" ]]; then
        local routing=
        if [[ -n "${protocol}" ]]; then
            routing=$(jq -r "del(.routing.rules[] | select(.${type} == \"${tag}\" and (.protocol | index(\"${protocol}\"))))" ${configPath}09_routing.json)
            echo "${routing}" | jq . >${configPath}09_routing.json
        else
            routing=$(jq -r "del(.routing.rules[] | select(.${type} == \"${tag}\" and (.protocol == null )))" ${configPath}09_routing.json)
            echo "${routing}" | jq . >${configPath}09_routing.json
        fi
    fi
}

# 卸载嗅探
unInstallSniffing() {

    find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
        if grep -q "destOverride" <"${configPath}${inbound}"; then
            sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
            echo "${sniffing}" | jq . >"${configPath}${inbound}"
        fi
    done

}

# 安装嗅探 (已移除，仅Xray需要)
installSniffing() {
    :
}

# 读取第三方warp配置
readConfigWarpReg() {
    if [[ ! -f "/etc/v2ray-agent/warp/config" ]]; then
        /etc/v2ray-agent/warp/warp-reg >/etc/v2ray-agent/warp/config
    fi

    secretKeyWarpReg=$(grep <"/etc/v2ray-agent/warp/config" private_key | awk '{print $2}')

    addressWarpReg=$(grep <"/etc/v2ray-agent/warp/config" v6 | awk '{print $2}')

    publicKeyWarpReg=$(grep <"/etc/v2ray-agent/warp/config" public_key | awk '{print $2}')

    reservedWarpReg=$(grep <"/etc/v2ray-agent/warp/config" reserved | awk -F "[:]" '{print $2}')

}
# 安装warp-reg工具
installWarpReg() {
    if [[ ! -f "/etc/v2ray-agent/warp/warp-reg" ]]; then
        echo
        echoContent yellow "# 注意事项"
        echoContent yellow "# 依赖第三方程序，请熟知其中风险"
        echoContent yellow "# 项目地址：https://github.com/badafans/warp-reg \n"

        read -r -p "warp-reg未安装，是否安装 ？[y/n]:" installWarpRegStatus

        if [[ "${installWarpRegStatus}" == "y" ]]; then

            curl -sLo /etc/v2ray-agent/warp/warp-reg "https://github.com/badafans/warp-reg/releases/download/v1.0/${warpRegCoreCPUVendor}"
            chmod 655 /etc/v2ray-agent/warp/warp-reg

        else
            echoContent yellow " ---> 放弃安装"
            exit 0
        fi
    fi
}

# 展示warp分流域名
showWireGuardDomain() {
    local type=$1
    # sing-box
    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ -f "${singBoxConfigPath}wireguard_endpoints_${type}_route.json" ]]; then
            echoContent yellow "sing-box"
            jq -r -c '.route.rules[]' "${singBoxConfigPath}wireguard_endpoints_${type}_route.json" | jq -r
        elif [[ ! -f "${singBoxConfigPath}wireguard_endpoints_${type}_route.json" && -f "${singBoxConfigPath}wireguard_endpoints_${type}.json" ]]; then
            echoContent yellow "sing-box"
            echoContent green " ---> 已设置warp ${type}全局分流"
        else
            echoContent yellow " ---> 未安装warp ${type}分流"
        fi
    fi

}

# 添加WireGuard分流
addWireGuardRoute() {
    local type=$1
    local tag=$2
    local domainList=$3
    # sing-box
    if [[ -n "${singBoxConfigPath}" ]]; then

        # rule
        addSingBoxRouteRule "wireguard_endpoints_${type}" "${domainList}" "wireguard_endpoints_${type}_route"
        # addSingBoxOutbound "wireguard_out_${type}" "wireguard_out"
        if [[ -n "${domainList}" ]]; then
            addSingBoxOutbound "01_direct_outbound"
        fi

        # outbound
        addSingBoxWireGuardEndpoints "${type}"
    fi
}

# 卸载wireGuard
unInstallWireGuard() {
    local type=$1
    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ ! -f "${singBoxConfigPath}wireguard_endpoints_IPv6_route.json" && ! -f "${singBoxConfigPath}wireguard_endpoints_IPv4_route.json" ]]; then
            rm "${singBoxConfigPath}wireguard_outbound.json" >/dev/null 2>&1
            rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
        fi
    fi
}
# 移除WireGuard分流
removeWireGuardRoute() {
    local type=$1
    # sing-box
    if [[ -n "${singBoxConfigPath}" ]]; then
        removeSingBoxRouteRule "wireguard_endpoints_${type}"
    fi

    unInstallWireGuard "${type}"
}
# warp分流-第三方IPv4
warpRoutingReg() {
    local type=$2
    echoContent skyBlue "\n进度  $1/${totalProgress} : WARP分流[第三方]"
    echoContent red "=============================================================="

    echoContent yellow "1.查看已分流域名"
    echoContent yellow "2.添加域名"
    echoContent yellow "3.设置WARP全局"
    echoContent yellow "4.卸载WARP分流"
    echoContent red "=============================================================="
    read -r -p "请选择:" warpStatus
    installWarpReg
    readConfigWarpReg
    local address=
    if [[ ${type} == "IPv4" ]]; then
        address="172.16.0.2/32"
    elif [[ ${type} == "IPv6" ]]; then
        address="${addressWarpReg}/128"
    else
        echoContent red " ---> IP获取失败，退出安装"
    fi

    if [[ "${warpStatus}" == "1" ]]; then
        showWireGuardDomain "${type}"
        exit 0
    elif [[ "${warpStatus}" == "2" ]]; then
        echoContent yellow "# 注意事项"
        echoContent yellow "# 支持sing-box"
        echoContent yellow "# 使用教程：https://www.v2ray-agent.com/archives/1683226921000 \n"

        read -r -p "请按照上面示例录入域名:" domainList
        addWireGuardRoute "${type}" outboundTag "${domainList}"
        echoContent green " ---> 添加完毕"

    elif [[ "${warpStatus}" == "3" ]]; then

        echoContent red "=============================================================="
        echoContent yellow "# 注意事项\n"
        echoContent yellow "1.会删除所有设置的分流规则"
        echoContent yellow "2.会删除除WARP[第三方]之外的所有出站规则\n"
        read -r -p "是否确认设置？[y/n]:" warpOutStatus

        if [[ "${warpOutStatus}" == "y" ]]; then
            readConfigWarpReg
            if [[ -n "${singBoxConfigPath}" ]]; then

                removeSingBoxConfig IPv4_out
                removeSingBoxConfig IPv6_out
                removeSingBoxConfig 01_direct_outbound

                # 删除所有分流规则
                removeSingBoxConfig wireguard_endpoints_IPv4_route
                removeSingBoxConfig wireguard_endpoints_IPv6_route

                removeSingBoxConfig IPv6_route
                removeSingBoxConfig socks5_02_inbound_route

                addSingBoxWireGuardEndpoints "${type}"
                addWireGuardRoute "${type}" outboundTag ""
                if [[ "${type}" == "IPv4" ]]; then
                    removeSingBoxConfig wireguard_endpoints_IPv6
                else
                    removeSingBoxConfig wireguard_endpoints_IPv4
                fi

                # outbound
                # addSingBoxOutbound "wireguard_out_${type}" "wireguard_out"

            fi

            echoContent green " ---> WARP全局出站设置完毕"
        else
            echoContent green " ---> 放弃设置"
            exit 0
        fi

    elif [[ "${warpStatus}" == "4" ]]; then
        if [[ -n "${singBoxConfigPath}" ]]; then
            removeSingBoxConfig "wireguard_endpoints_${type}_route"

            removeSingBoxConfig "wireguard_endpoints_${type}"
            addSingBoxOutbound "01_direct_outbound"
        fi

        echoContent green " ---> 卸载WARP ${type}分流完毕"
    else

        echoContent red " ---> 选择错误"
        exit 0
    fi
    reloadCore
}

# 重启核心
reloadCore() {
    readInstallType
    handleSingBox stop
    handleSingBox start
}

# 列出已安装的入站协议
listInstalledInbounds() {
    local configDir="/etc/v2ray-agent/sing-box/conf/config"

    for file in "${configDir}"/*_inbounds.json; do
        if [[ -f "$file" ]]; then
            local tag
            local type
            local port
            tag=$(jq -r '.inbounds[0].tag' "$file" 2>/dev/null)
            type=$(jq -r '.inbounds[0].type' "$file" 2>/dev/null)
            port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null)
            if [[ -n "$tag" && "$tag" != "null" ]]; then
                echo "${tag}|${type}|${port}|${file##*/}"
            fi
        fi
    done
}

# 分流工具菜单
inboundRoutingMenu() {
    echoContent skyBlue "\n功能 1/${totalProgress} : 分流工具"
    echoContent red "\n=============================================================="
    echoContent yellow "# 按入站协议分流，将指定入站的所有流量转发到出站服务器\n"

    echoContent yellow "1.添加分流"
    echoContent yellow "2.查看分流"
    echoContent yellow "3.删除分流"
    read -r -p "请选择:" selectType

    case ${selectType} in
    1)
        addInboundRouting
        ;;
    2)
        showInboundRouting
        ;;
    3)
        removeInboundRouting
        ;;
    esac
}

# 添加入站分流
addInboundRouting() {
    readInstallType
    if [[ -z "${coreInstallType}" ]]; then
        echoContent red " ---> 未安装任何协议，请先安装"
        exit 0
    fi

    echoContent skyBlue "\n已安装的入站协议："
    echoContent red "=============================================================="

    local inboundList
    inboundList=$(listInstalledInbounds)

    if [[ -z "$inboundList" ]]; then
        echoContent red " ---> 未找到已安装的入站协议"
        exit 0
    fi

    local i=1
    local tags=()
    while IFS='|' read -r tag type port file; do
        echoContent yellow "${i}. ${tag} (${type}, 端口:${port})"
        tags+=("$tag")
        ((i++))
    done <<< "$inboundList"

    echo
    read -r -p "请选择要分流的入站[1-$((i-1))]:" selectInbound

    if [[ -z "$selectInbound" ]] || [[ "$selectInbound" -lt 1 ]] || [[ "$selectInbound" -ge "$i" ]]; then
        echoContent red " ---> 选择错误"
        exit 0
    fi

    local selectedTag="${tags[$((selectInbound-1))]}"

    # 检查是否已有分流规则
    if [[ -f "${singBoxConfigPath}route_${selectedTag}_socks5.json" ]]; then
        echoContent red " ---> 该入站已配置分流规则，请先删除"
        exit 0
    fi

    configureSocks5Outbound "$selectedTag"
}

# 配置 Socks5 出站
configureSocks5Outbound() {
    local inboundTag=$1

    echoContent skyBlue "\n==================== 配置 Socks5 出站 =====================\n"

    read -r -p "请输入Socks5服务器地址:" socks5Server
    if [[ -z "$socks5Server" ]]; then
        echoContent red " ---> 服务器地址不可为空"
        exit 0
    fi

    read -r -p "请输入Socks5端口:" socks5Port
    if [[ -z "$socks5Port" ]]; then
        echoContent red " ---> 端口不可为空"
        exit 0
    fi

    read -r -p "请输入用户名(可选，回车跳过):" socks5User
    read -r -p "请输入密码(可选，回车跳过):" socks5Pass

    local outboundTag="socks5_out_${inboundTag}"
    local routeFile="route_${inboundTag}_socks5"

    # 创建 socks5 出站配置
    if [[ -n "$socks5User" && -n "$socks5Pass" ]]; then
        cat <<EOF >"${singBoxConfigPath}${outboundTag}.json"
{
    "outbounds":[
        {
            "type": "socks",
            "tag": "${outboundTag}",
            "server": "${socks5Server}",
            "server_port": ${socks5Port},
            "version": "5",
            "username": "${socks5User}",
            "password": "${socks5Pass}"
        }
    ]
}
EOF
    else
        cat <<EOF >"${singBoxConfigPath}${outboundTag}.json"
{
    "outbounds":[
        {
            "type": "socks",
            "tag": "${outboundTag}",
            "server": "${socks5Server}",
            "server_port": ${socks5Port},
            "version": "5"
        }
    ]
}
EOF
    fi

    # 创建路由规则（基于 inbound tag）
    cat <<EOF >"${singBoxConfigPath}${routeFile}.json"
{
    "route":{
        "rules":[
            {
                "inbound": ["${inboundTag}"],
                "outbound": "${outboundTag}"
            }
        ]
    }
}
EOF

    reloadCore
    echoContent green " ---> 分流配置成功"
    echoContent yellow " 入站: ${inboundTag} -> 出站: ${socks5Server}:${socks5Port}"
}

# 查看入站分流
showInboundRouting() {
    echoContent skyBlue "\n当前分流配置："
    echoContent red "=============================================================="

    local found=false
    for file in "${singBoxConfigPath}"route_*_socks5.json; do
        if [[ -f "$file" ]]; then
            found=true
            local inbound
            local outboundTag
            local outboundFile
            local server
            local port

            inbound=$(jq -r '.route.rules[0].inbound[0]' "$file")
            outboundTag=$(jq -r '.route.rules[0].outbound' "$file")
            outboundFile="${singBoxConfigPath}${outboundTag}.json"

            if [[ -f "$outboundFile" ]]; then
                server=$(jq -r '.outbounds[0].server' "$outboundFile")
                port=$(jq -r '.outbounds[0].server_port' "$outboundFile")
                echoContent yellow " ${inbound} -> ${server}:${port}"
            else
                echoContent yellow " ${inbound} -> ${outboundTag}"
            fi
        fi
    done

    if [[ "$found" == "false" ]]; then
        echoContent yellow " 暂无分流配置"
    fi
}

# 删除入站分流
removeInboundRouting() {
    echoContent skyBlue "\n删除分流配置"
    echoContent red "=============================================================="

    local routeFiles=()
    local i=1

    for file in "${singBoxConfigPath}"route_*_socks5.json; do
        if [[ -f "$file" ]]; then
            local inbound
            local outboundTag
            inbound=$(jq -r '.route.rules[0].inbound[0]' "$file")
            outboundTag=$(jq -r '.route.rules[0].outbound' "$file")
            echoContent yellow "${i}. ${inbound} -> ${outboundTag}"
            routeFiles+=("$file|$outboundTag")
            ((i++))
        fi
    done

    if [[ ${#routeFiles[@]} -eq 0 ]]; then
        echoContent yellow " 暂无分流配置"
        exit 0
    fi

    echo
    read -r -p "请选择要删除的分流[1-$((i-1))]:" selectRoute

    if [[ -z "$selectRoute" ]] || [[ "$selectRoute" -lt 1 ]] || [[ "$selectRoute" -ge "$i" ]]; then
        echoContent red " ---> 选择错误"
        exit 0
    fi

    local selected="${routeFiles[$((selectRoute-1))]}"
    local routeFile="${selected%|*}"
    local outboundTag="${selected#*|}"

    # 删除路由规则文件
    rm -f "$routeFile"
    # 删除出站配置文件
    rm -f "${singBoxConfigPath}${outboundTag}.json"

    reloadCore
    echoContent green " ---> 删除成功"
}

# sing-box 个性化安装
customSingBoxInstall() {
    echoContent skyBlue "\n========================个性化安装============================"
    echoContent yellow "0.VLESS+Vision+TCP"
    echoContent yellow "1.VLESS+TLS+WS[仅CDN推荐]"
    echoContent yellow "3.VMess+TLS+WS[仅CDN推荐]"
    echoContent yellow "4.Trojan+TLS[不推荐]"
    echoContent yellow "6.Hysteria2"
    echoContent yellow "7.VLESS+Reality+Vision"
    echoContent yellow "8.VLESS+Reality+gRPC"
    echoContent yellow "9.Tuic"
    echoContent yellow "10.Naive"
    echoContent yellow "11.VMess+TLS+HTTPUpgrade"
    echoContent yellow "13.anytls"
    echoContent yellow "14.Socks5入站"

    read -r -p "请选择[多选]，[例如:1,2,3]:" selectCustomInstallType
    echoContent skyBlue "--------------------------------------------------------------"
    if echo "${selectCustomInstallType}" | grep -q "，"; then
        echoContent red " ---> 请使用英文逗号分隔"
        exit 0
    fi
    if [[ "${selectCustomInstallType}" != "10" ]] && [[ "${selectCustomInstallType}" != "11" ]] && [[ "${selectCustomInstallType}" != "13" ]] && [[ "${selectCustomInstallType}" != "14" ]] && ((${#selectCustomInstallType} >= 2)) && ! echo "${selectCustomInstallType}" | grep -q ","; then
        echoContent red " ---> 多选请使用英文逗号分隔"
        exit 0
    fi
    if [[ "${selectCustomInstallType: -1}" != "," ]]; then
        selectCustomInstallType="${selectCustomInstallType},"
    fi
    if [[ "${selectCustomInstallType:0:1}" != "," ]]; then
        selectCustomInstallType=",${selectCustomInstallType},"
    fi

    if [[ "${selectCustomInstallType//,/}" =~ ^[0-9]+$ ]]; then
        readLastInstallationConfig
        unInstallSubscribe
        totalProgress=9
        installTools 1
        # 申请tls
        if echo "${selectCustomInstallType}" | grep -q -E ",0,|,1,|,3,|,4,|,6,|,9,|,10,|,11,|,13,"; then
            initTLSNginxConfig 2
            installTLS 3
            handleNginx stop
        fi

        installSingBox 4
        installSingBoxService 5
        initSingBoxConfig custom 6
        installCronTLS 7
        handleSingBox stop
        handleSingBox start
        handleNginx stop
        handleNginx start
        # 生成账号
        checkGFWStatue 8
        showAccounts 9
    else
        echoContent red " ---> 输入不合法"
        customSingBoxInstall
    fi
}

# 安装 sing-box
selectCoreInstall() {
    if [[ "${selectInstallType}" == "2" ]]; then
        customSingBoxInstall
    else
        singBoxInstall
    fi
}

# sing-box 全部安装
singBoxInstall() {
    readLastInstallationConfig
    unInstallSubscribe
    checkBTPanel
    check1Panel
    selectCustomInstallType=
    totalProgress=8
    installTools 2

    if [[ -n "${btDomain}" ]]; then
        echoContent skyBlue "\n进度  3/${totalProgress} : 检测到宝塔面板/1Panel，跳过申请TLS步骤"
        customPortFunction
    else
        # 申请tls
        initTLSNginxConfig 3
        installTLS 4
    fi

    handleNginx stop

    installSingBox 5
    installSingBoxService 6
    initSingBoxConfig all 7

    installCronTLS 8

    handleSingBox stop
    handleSingBox start
    handleNginx stop
    handleNginx start
    # 生成账号
    showAccounts 9
}

# sing-box 版本管理
coreVersionManageMenu() {
    singBoxVersionManageMenu 1
}
# 定时任务检查
cronFunction() {
    if [[ "${cronName}" == "RenewTLS" ]]; then
        renewalTLS
        exit 0
    fi
}
# 账号管理
manageAccount() {
    echoContent skyBlue "\n功能 1/${totalProgress} : 账号管理"
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> 未安装"
        exit 0
    fi

    echoContent red "\n=============================================================="
    echoContent yellow "# 添加单个用户时可自定义email和uuid"
    echoContent yellow "# 如安装了Hysteria或者Tuic，账号会同时添加到相应的类型下面\n"
    echoContent yellow "1.查看账号"
    echoContent yellow "2.查看订阅"
    echoContent yellow "3.管理其他订阅"
    echoContent yellow "4.添加用户"
    echoContent yellow "5.删除用户"
    echoContent red "=============================================================="
    read -r -p "请输入:" manageAccountStatus
    if [[ "${manageAccountStatus}" == "1" ]]; then
        showAccounts 1
    elif [[ "${manageAccountStatus}" == "2" ]]; then
        subscribe
    elif [[ "${manageAccountStatus}" == "3" ]]; then
        addSubscribeMenu 1
    elif [[ "${manageAccountStatus}" == "4" ]]; then
        addUser
    elif [[ "${manageAccountStatus}" == "5" ]]; then
        removeUser
    else
        echoContent red " ---> 选择错误"
    fi
}

# 安装订阅
installSubscribe() {
    readNginxSubscribe
    local nginxSubscribeListen=
    local nginxSubscribeSSL=
    local serverName=
    local SSLType=
    local listenIPv6=
    if [[ -z "${subscribePort}" ]]; then

        nginxVersion=$(nginx -v 2>&1)

        if echo "${nginxVersion}" | grep -q "not found" || [[ -z "${nginxVersion}" ]]; then
            echoContent yellow "未检测到nginx，无法使用订阅服务\n"
            read -r -p "是否安装[y/n]？" installNginxStatus
            if [[ "${installNginxStatus}" == "y" ]]; then
                installNginxTools
            else
                echoContent red " ---> 放弃安装nginx\n"
                exit 0
            fi
        fi
        echoContent yellow "开始配置订阅，请输入订阅的端口\n"

        mapfile -t result < <(initSingBoxPort "${subscribePort}")
        echo
        echoContent yellow " ---> 开始配置订阅的伪装站点\n"
        nginxBlog
        echo
        local httpSubscribeStatus=

        if ! echo "${selectCustomInstallType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,|,11,|,13," && ! echo "${currentInstallProtocolType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,|,11,|,13," && [[ -z "${domain}" ]]; then
            httpSubscribeStatus=true
        fi

        if [[ "${httpSubscribeStatus}" == "true" ]]; then

            echoContent yellow "未发现tls证书，使用无加密订阅，可能被运营商拦截，请注意风险。"
            echo
            read -r -p "是否使用http订阅[y/n]？" addNginxSubscribeStatus
            echo
            if [[ "${addNginxSubscribeStatus}" != "y" ]]; then
                echoContent yellow " ---> 退出安装"
                exit
            fi
        else
            local subscribeServerName=
            if [[ -n "${currentHost}" ]]; then
                subscribeServerName="${currentHost}"
            else
                subscribeServerName="${domain}"
            fi

            SSLType="ssl"
            serverName="server_name ${subscribeServerName};"
            nginxSubscribeSSL="ssl_certificate /etc/v2ray-agent/tls/${subscribeServerName}.crt;ssl_certificate_key /etc/v2ray-agent/tls/${subscribeServerName}.key;"
        fi
        if [[ -n "$(curl --connect-timeout 2 -s -6 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)" ]]; then
            listenIPv6="listen [::]:${result[-1]} ${SSLType};"
        fi
        if echo "${nginxVersion}" | grep -q "1.25" && [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $3}') -gt 0 ]] || [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $2}') -gt 25 ]]; then
            nginxSubscribeListen="listen ${result[-1]} ${SSLType} so_keepalive=on;http2 on;${listenIPv6}"
        else
            nginxSubscribeListen="listen ${result[-1]} ${SSLType} so_keepalive=on;${listenIPv6}"
        fi

        cat <<EOF >${nginxConfigPath}subscribe.conf
server {
    ${nginxSubscribeListen}
    ${serverName}
    ${nginxSubscribeSSL}
    ssl_protocols              TLSv1.2 TLSv1.3;
    ssl_ciphers                TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers  on;

    resolver                   1.1.1.1 valid=60s;
    resolver_timeout           2s;
    client_max_body_size 100m;
    root ${nginxStaticPath};
    location ~ ^/s/(clashMeta|default|clashMetaProfiles|sing-box|sing-box_profiles)/(.*) {
        default_type 'text/plain; charset=utf-8';
        alias /etc/v2ray-agent/subscribe/\$1/\$2;
    }
    location / {
    }
}
EOF
        bootStartup nginx
        handleNginx stop
        handleNginx start
    fi
    if [[ -z $(pgrep -f "nginx") ]]; then
        handleNginx start
    fi
}
# 卸载订阅
unInstallSubscribe() {
    rm -rf ${nginxConfigPath}subscribe.conf >/dev/null 2>&1
}

# 添加订阅
addSubscribeMenu() {
    echoContent skyBlue "\n===================== 添加其他机器订阅 ======================="
    echoContent yellow "1.添加"
    echoContent yellow "2.移除"
    echoContent red "=============================================================="
    read -r -p "请选择:" addSubscribeStatus
    if [[ "${addSubscribeStatus}" == "1" ]]; then
        addOtherSubscribe
    elif [[ "${addSubscribeStatus}" == "2" ]]; then
        if [[ ! -f "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" ]]; then
            echoContent green " ---> 未安装其他订阅"
            exit 0
        fi
        grep -v '^$' "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" | awk '{print NR""":"$0}'
        read -r -p "请选择要删除的订阅编号[仅支持单个删除]:" delSubscribeIndex
        if [[ -z "${delSubscribeIndex}" ]]; then
            echoContent green " ---> 不可以为空"
            exit 0
        fi

        sed -i "$((delSubscribeIndex))d" "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" >/dev/null 2>&1

        echoContent green " ---> 其他机器订阅删除成功"
        subscribe
    fi
}
# 添加其他机器clashMeta订阅
addOtherSubscribe() {
    echoContent yellow "#注意事项:"
    echoContent yellow "请仔细阅读以下文章： https://www.v2ray-agent.com/archives/1681804748677"
    echoContent skyBlue "录入示例：www.v2ray-agent.com:443:vps1\n"
    read -r -p "请输入域名 端口 机器别名:" remoteSubscribeUrl
    if [[ -z "${remoteSubscribeUrl}" ]]; then
        echoContent red " ---> 不可为空"
        addOtherSubscribe
    elif ! echo "${remoteSubscribeUrl}" | grep -q ":"; then
        echoContent red " ---> 规则不合法"
    else

        if [[ -f "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" ]] && grep -q "${remoteSubscribeUrl}" /etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl; then
            echoContent red " ---> 此订阅已添加"
            exit 0
        fi
        echo
        read -r -p "是否是HTTP订阅？[y/n]" httpSubscribeStatus
        if [[ "${httpSubscribeStatus}" == "y" ]]; then
            remoteSubscribeUrl="${remoteSubscribeUrl}:http"
        fi
        echo "${remoteSubscribeUrl}" >>/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl
        subscribe
    fi
}
# clashMeta配置文件
clashMetaConfig() {
    local url=$1
    local id=$2
    cat <<EOF >"/etc/v2ray-agent/subscribe/clashMetaProfiles/${id}"
log-level: debug
mode: rule
ipv6: true
mixed-port: 7890
allow-lan: true
bind-address: "*"
lan-allowed-ips:
  - 0.0.0.0/0
  - ::/0
find-process-mode: strict
external-controller: 0.0.0.0:9090

geox-url:
  geoip: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
geo-auto-update: true
geo-update-interval: 24

external-controller-cors:
  allow-private-network: true

global-client-fingerprint: chrome

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  override-destination: false
  sniff:
    QUIC:
      ports: [ 443 ]
    TLS:
      ports: [ 443 ]
    HTTP:
      ports: [80]


dns:
  enable: true
  prefer-h3: false
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - 'dns.google'
    - "localhost.ptlogin2.qq.com"
  use-hosts: true
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  nameserver-policy:
    "geosite:cn,private":
      - https://doh.pub/dns-query
      - https://dns.alidns.com/dns-query

proxy-providers:
  ${subscribeSalt}_provider:
    type: http
    path: ./${subscribeSalt}_provider.yaml
    url: ${url}
    interval: 3600
    proxy: DIRECT
    health-check:
      enable: true
      url: https://cp.cloudflare.com/generate_204
      interval: 300

proxy-groups:
  - name: 手动切换
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies: null
  - name: 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 36000
    tolerance: 50
    use:
      - ${subscribeSalt}_provider
    proxies: null

  - name: 全球代理
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择

  - name: 流媒体
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
      - DIRECT
  - name: DNS_Proxy
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 自动选择
      - 手动切换
      - DIRECT

  - name: Telegram
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
  - name: Google
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
      - DIRECT
  - name: YouTube
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
  - name: Netflix
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
  - name: Spotify
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
      - DIRECT
  - name: HBO
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
  - name: Bing
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择


  - name: OpenAI
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择

  - name: ClaudeAI
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择

  - name: Disney
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
  - name: GitHub
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
      - DIRECT

  - name: 国内媒体
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - DIRECT
  - name: 本地直连
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - DIRECT
      - 自动选择
  - name: 漏网之鱼
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - DIRECT
      - 手动切换
      - 自动选择
rule-providers:
  lan:
    type: http
    behavior: classical
    interval: 86400
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Lan/Lan.yaml
    path: ./Rules/lan.yaml
  reject:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt
    path: ./ruleset/reject.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt
    path: ./ruleset/gfw.yaml
    interval: 86400
  greatfire:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt
    path: ./ruleset/greatfire.yaml
    interval: 86400
  tld-not-cn:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt
    path: ./ruleset/tld-not-cn.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt
    path: ./ruleset/applications.yaml
    interval: 86400
  Disney:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.yaml
    path: ./ruleset/disney.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.yaml
    path: ./ruleset/netflix.yaml
    interval: 86400
  YouTube:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml
    path: ./ruleset/youtube.yaml
    interval: 86400
  HBO:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/HBO/HBO.yaml
    path: ./ruleset/hbo.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml
    path: ./ruleset/openai.yaml
    interval: 86400
  ClaudeAI:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml
    path: ./ruleset/claudeai.yaml
    interval: 86400
  Bing:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Bing/Bing.yaml
    path: ./ruleset/bing.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml
    path: ./ruleset/google.yaml
    interval: 86400
  GitHub:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml
    path: ./ruleset/github.yaml
    interval: 86400
  Spotify:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml
    path: ./ruleset/spotify.yaml
    interval: 86400
  ChinaMaxDomain:
    type: http
    behavior: domain
    interval: 86400
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml
    path: ./Rules/ChinaMaxDomain.yaml
  ChinaMaxIPNoIPv6:
    type: http
    behavior: ipcidr
    interval: 86400
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_IP_No_IPv6.yaml
    path: ./Rules/ChinaMaxIPNoIPv6.yaml
rules:
  - RULE-SET,YouTube,YouTube,no-resolve
  - RULE-SET,Google,Google,no-resolve
  - RULE-SET,GitHub,GitHub
  - RULE-SET,telegramcidr,Telegram,no-resolve
  - RULE-SET,Spotify,Spotify,no-resolve
  - RULE-SET,Netflix,Netflix
  - RULE-SET,HBO,HBO
  - RULE-SET,Bing,Bing
  - RULE-SET,OpenAI,OpenAI
  - RULE-SET,ClaudeAI,ClaudeAI
  - RULE-SET,Disney,Disney
  - RULE-SET,proxy,全球代理
  - RULE-SET,gfw,全球代理
  - RULE-SET,applications,本地直连
  - RULE-SET,ChinaMaxDomain,本地直连
  - RULE-SET,ChinaMaxIPNoIPv6,本地直连,no-resolve
  - RULE-SET,lan,本地直连,no-resolve
  - GEOIP,CN,本地直连
  - MATCH,漏网之鱼
EOF

}
# 随机salt
initRandomSalt() {
    local chars="abcdefghijklmnopqrtuxyz"
    local initCustomPath=
    for i in {1..10}; do
        echo "${i}" >/dev/null
        initCustomPath+="${chars:RANDOM%${#chars}:1}"
    done
    echo "${initCustomPath}"
}
# 订阅
subscribe() {
    readInstallProtocolType
    installSubscribe

    readNginxSubscribe
    local renewSalt=$1
    local showStatus=$2
    if [[ "${coreInstallType}" == "2" ]]; then

        echoContent skyBlue "-------------------------备注---------------------------------"
        echoContent yellow "# 查看订阅会重新生成本地账号的订阅"
        echoContent red "# 需要手动输入md5加密的salt值，如果不了解使用随机即可"
        echoContent yellow "# 不影响已添加的远程订阅的内容\n"

        if [[ -f "/etc/v2ray-agent/subscribe_local/subscribeSalt" && -n $(cat "/etc/v2ray-agent/subscribe_local/subscribeSalt") ]]; then
            if [[ -z "${renewSalt}" ]]; then
                read -r -p "读取到上次安装设置的Salt，是否使用上次生成的Salt ？[y/n]:" historySaltStatus
                if [[ "${historySaltStatus}" == "y" ]]; then
                    subscribeSalt=$(cat /etc/v2ray-agent/subscribe_local/subscribeSalt)
                else
                    read -r -p "请输入salt值, [回车]使用随机:" subscribeSalt
                fi
            else
                subscribeSalt=$(cat /etc/v2ray-agent/subscribe_local/subscribeSalt)
            fi
        else
            read -r -p "请输入salt值, [回车]使用随机:" subscribeSalt
            showStatus=
        fi

        if [[ -z "${subscribeSalt}" ]]; then
            subscribeSalt=$(initRandomSalt)
        fi
        echoContent yellow "\n ---> Salt: ${subscribeSalt}"

        echo "${subscribeSalt}" >/etc/v2ray-agent/subscribe_local/subscribeSalt

        rm -rf /etc/v2ray-agent/subscribe/default/*
        rm -rf /etc/v2ray-agent/subscribe/clashMeta/*
        rm -rf /etc/v2ray-agent/subscribe_local/default/*
        rm -rf /etc/v2ray-agent/subscribe_local/clashMeta/*
        rm -rf /etc/v2ray-agent/subscribe_local/sing-box/*
        showAccounts >/dev/null
        if [[ -n $(ls /etc/v2ray-agent/subscribe_local/default/) ]]; then
            if [[ -f "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" && -n $(cat "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl") ]]; then
                if [[ -z "${renewSalt}" ]]; then
                    read -r -p "读取到其他订阅，是否更新？[y/n]" updateOtherSubscribeStatus
                else
                    updateOtherSubscribeStatus=y
                fi
            fi
            local subscribePortLocal="${subscribePort}"
            find /etc/v2ray-agent/subscribe_local/default/* | while read -r email; do
                email=$(echo "${email}" | awk -F "[d][e][f][a][u][l][t][/]" '{print $2}')

                local emailMd5=
                emailMd5=$(echo -n "${email}${subscribeSalt}"$'\n' | md5sum | awk '{print $1}')

                cat "/etc/v2ray-agent/subscribe_local/default/${email}" >>"/etc/v2ray-agent/subscribe/default/${emailMd5}"
                if [[ "${updateOtherSubscribeStatus}" == "y" ]]; then
                    updateRemoteSubscribe "${emailMd5}" "${email}"
                fi
                local base64Result
                base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/default/${emailMd5}")
                echo "${base64Result}" >"/etc/v2ray-agent/subscribe/default/${emailMd5}"
                echoContent yellow "--------------------------------------------------------------"
                local currentDomain=${currentHost}

                if [[ -n "${currentDefaultPort}" && "${currentDefaultPort}" != "443" ]]; then
                    currentDomain="${currentHost}:${currentDefaultPort}"
                fi
                if [[ -n "${subscribePortLocal}" ]]; then
                    if [[ "${subscribeType}" == "http" ]]; then
                        currentDomain="$(getPublicIP):${subscribePort}"
                    else
                        currentDomain="${currentHost}:${subscribePort}"
                    fi
                fi
                if [[ -z "${showStatus}" ]]; then
                    echoContent skyBlue "\n----------默认订阅----------\n"
                    echoContent green "email:${email}\n"
                    echoContent yellow "url:${subscribeType}://${currentDomain}/s/default/${emailMd5}\n"
                    echoContent yellow "在线二维码:https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${subscribeType}://${currentDomain}/s/default/${emailMd5}\n"
                    if [[ "${release}" != "alpine" ]]; then
                        echo "${subscribeType}://${currentDomain}/s/default/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                    fi

                    # clashMeta
                    if [[ -f "/etc/v2ray-agent/subscribe_local/clashMeta/${email}" ]]; then

                        cat "/etc/v2ray-agent/subscribe_local/clashMeta/${email}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"

                        sed -i '1i\proxies:' "/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"

                        local clashProxyUrl="${subscribeType}://${currentDomain}/s/clashMeta/${emailMd5}"
                        clashMetaConfig "${clashProxyUrl}" "${emailMd5}"
                        echoContent skyBlue "\n----------clashMeta订阅----------\n"
                        echoContent yellow "url:${subscribeType}://${currentDomain}/s/clashMetaProfiles/${emailMd5}\n"
                        echoContent yellow "在线二维码:https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${subscribeType}://${currentDomain}/s/clashMetaProfiles/${emailMd5}\n"
                        if [[ "${release}" != "alpine" ]]; then
                            echo "${subscribeType}://${currentDomain}/s/clashMetaProfiles/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                        fi

                    fi
                    # sing-box
                    if [[ -f "/etc/v2ray-agent/subscribe_local/sing-box/${email}" ]]; then
                        cp "/etc/v2ray-agent/subscribe_local/sing-box/${email}" "/etc/v2ray-agent/subscribe/sing-box_profiles/${emailMd5}"

                        echoContent skyBlue " ---> 下载 sing-box 通用配置文件"
                        if [[ "${release}" == "alpine" ]]; then
                            wget -O "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" -q "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/documents/sing-box.json"
                        else
                            wget -O "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" -q "${wgetShowProgressStatus}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/documents/sing-box.json"
                        fi

                        jq ".outbounds=$(jq ".outbounds|map(if has(\"outbounds\") then .outbounds += $(jq ".|map(.tag)" "/etc/v2ray-agent/subscribe_local/sing-box/${email}") else . end)" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}")" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" >"/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" && mv "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}"
                        jq ".outbounds += $(jq '.' "/etc/v2ray-agent/subscribe_local/sing-box/${email}")" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" >"/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" && mv "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}"

                        echoContent skyBlue "\n----------sing-box订阅----------\n"
                        echoContent yellow "url:${subscribeType}://${currentDomain}/s/sing-box/${emailMd5}\n"
                        echoContent yellow "在线二维码:https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${subscribeType}://${currentDomain}/s/sing-box/${emailMd5}\n"
                        if [[ "${release}" != "alpine" ]]; then
                            echo "${subscribeType}://${currentDomain}/s/sing-box/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                        fi

                    fi

                    echoContent skyBlue "--------------------------------------------------------------"
                else
                    echoContent green " ---> email:${email}，订阅已更新，请使用客户端重新拉取"
                fi

            done
        fi
    else
        echoContent red " ---> 未安装伪装站点，无法使用订阅服务"
    fi
}

# 更新远程订阅
updateRemoteSubscribe() {

    local emailMD5=$1
    local email=$2
    while read -r line; do
        local subscribeType=
        subscribeType="https"

        local serverAlias=
        serverAlias=$(echo "${line}" | awk -F "[:]" '{print $3}')

        local remoteUrl=
        remoteUrl=$(echo "${line}" | awk -F "[:]" '{print $1":"$2}')

        local subscribeTypeRemote=
        subscribeTypeRemote=$(echo "${line}" | awk -F "[:]" '{print $4}')

        if [[ -n "${subscribeTypeRemote}" ]]; then
            subscribeType="${subscribeTypeRemote}"
        fi
        local clashMetaProxies=

        clashMetaProxies=$(curl -s "${subscribeType}://${remoteUrl}/s/clashMeta/${emailMD5}" | sed '/proxies:/d' | sed "s/\"${email}/\"${email}_${serverAlias}/g")

        if ! echo "${clashMetaProxies}" | grep -q "nginx" && [[ -n "${clashMetaProxies}" ]]; then
            echo "${clashMetaProxies}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMD5}"
            echoContent green " ---> clashMeta订阅 ${remoteUrl}:${email} 更新成功"
        else
            echoContent red " ---> clashMeta订阅 ${remoteUrl}:${email}不存在"
        fi

        local default=
        default=$(curl -s "${subscribeType}://${remoteUrl}/s/default/${emailMD5}")

        if ! echo "${default}" | grep -q "nginx" && [[ -n "${default}" ]]; then
            default=$(echo "${default}" | base64 -d | sed "s/#${email}/#${email}_${serverAlias}/g")
            echo "${default}" >>"/etc/v2ray-agent/subscribe/default/${emailMD5}"

            echoContent green " ---> 通用订阅 ${remoteUrl}:${email} 更新成功"
        else
            echoContent red " ---> 通用订阅 ${remoteUrl}:${email} 不存在"
        fi

        local singBoxSubscribe=
        singBoxSubscribe=$(curl -s "${subscribeType}://${remoteUrl}/s/sing-box_profiles/${emailMD5}")

        if ! echo "${singBoxSubscribe}" | grep -q "nginx" && [[ -n "${singBoxSubscribe}" ]]; then
            singBoxSubscribe=${singBoxSubscribe//tag\": \"${email}/tag\": \"${email}_${serverAlias}}
            singBoxSubscribe=$(jq ". +=${singBoxSubscribe}" "/etc/v2ray-agent/subscribe_local/sing-box/${email}")
            echo "${singBoxSubscribe}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${email}"

            echoContent green " ---> 通用订阅 ${remoteUrl}:${email} 更新成功"
        else
            echoContent red " ---> 通用订阅 ${remoteUrl}:${email} 不存在"
        fi

    done < <(grep -v '^$' <"/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl")
}

# 切换alpn
switchAlpn() {
    echoContent skyBlue "\n功能 1/${totalProgress} : 切换alpn"
    if [[ -z ${currentAlpn} ]]; then
        echoContent red " ---> 无法读取alpn，请检查是否安装"
        exit 0
    fi

    echoContent red "\n=============================================================="
    echoContent green "当前alpn首位为:${currentAlpn}"
    echoContent yellow "  1.当http/1.1首位时，trojan可用，gRPC部分客户端可用【客户端支持手动选择alpn的可用】"
    echoContent yellow "  2.当h2首位时，gRPC可用，trojan部分客户端可用【客户端支持手动选择alpn的可用】"
    echoContent yellow "  3.如客户端不支持手动更换alpn，建议使用此功能更改服务端alpn顺序，来使用相应的协议"
    echoContent red "=============================================================="

    if [[ "${currentAlpn}" == "http/1.1" ]]; then
        echoContent yellow "1.切换alpn h2 首位"
    elif [[ "${currentAlpn}" == "h2" ]]; then
        echoContent yellow "1.切换alpn http/1.1 首位"
    else
        echoContent red '不符合'
    fi

    echoContent red "=============================================================="

    read -r -p "请选择:" selectSwitchAlpnType
    if [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "http/1.1" ]]; then

        local frontingTypeJSON
        frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn = [\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
        echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json

    elif [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "h2" ]]; then
        local frontingTypeJSON
        frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)
        echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json
    else
        echoContent red " ---> 选择错误"
        exit 0
    fi
    reloadCore
}

# 初始化realityKey
initRealityKey() {
    echoContent skyBlue "\n生成Reality key\n"
    if [[ -n "${currentRealityPublicKey}" && -z "${lastInstallationConfig}" ]]; then
        read -r -p "读取到上次安装记录，是否使用上次安装时的PublicKey/PrivateKey ？[y/n]:" historyKeyStatus
        if [[ "${historyKeyStatus}" == "y" ]]; then
            realityPrivateKey=${currentRealityPrivateKey}
            realityPublicKey=${currentRealityPublicKey}
        fi
    elif [[ -n "${currentRealityPublicKey}" && -n "${lastInstallationConfig}" ]]; then
        realityPrivateKey=${currentRealityPrivateKey}
        realityPublicKey=${currentRealityPublicKey}
    fi
    if [[ -z "${realityPrivateKey}" ]]; then
        realityX25519Key=$(/etc/v2ray-agent/sing-box/sing-box generate reality-keypair)
        realityPrivateKey=$(echo "${realityX25519Key}" | head -1 | awk '{print $2}')
        realityPublicKey=$(echo "${realityX25519Key}" | tail -n 1 | awk '{print $2}')
        echo "publicKey:${realityPublicKey}" >/etc/v2ray-agent/sing-box/conf/config/reality_key
    fi
}
# 检查reality域名是否符合
checkRealityDest() {
    local traceResult=
    traceResult=$(curl -s "https://$(echo "${realityDestDomain}" | cut -d ':' -f 1)/cdn-cgi/trace" | grep "visit_scheme=https")
    if [[ -n "${traceResult}" ]]; then
        echoContent red "\n ---> 检测到使用的域名，托管在cloudflare并开启了代理，使用此类型域名可能导致VPS流量被其他人使用[不建议使用]\n"
        read -r -p "是否继续 ？[y/n]" setRealityDestStatus
        if [[ "${setRealityDestStatus}" != 'y' ]]; then
            exit 0
        fi
        echoContent yellow "\n ---> 忽略风险，继续使用"
    fi
}

# 初始化客户端可用的ServersName
initRealityClientServersName() {
    local realityDestDomainList="gateway.icloud.com,itunes.apple.com,swdist.apple.com,swcdn.apple.com,updates.cdn-apple.com,mensura.cdn-apple.com,osxapps.itunes.apple.com,aod.itunes.apple.com,download-installer.cdn.mozilla.net,addons.mozilla.org,s0.awsstatic.com,d1.awsstatic.com,cdn-dynmedia-1.microsoft.com,images-na.ssl-images-amazon.com,m.media-amazon.com,player.live-video.net,one-piece.com,lol.secure.dyn.riotcdn.net,www.lovelive-anime.jp,academy.nvidia.com,software.download.prss.microsoft.com,dl.google.com,www.google-analytics.com,www.python.org,vuejs-jp.org,vuejs.org,zh-hk.vuejs.org,react.dev,www.java.com,www.oracle.com,www.mysql.com,www.mongodb.com,cname.vercel-dns.com,vercel-dns.com,www.swift.com,academy.nvidia.com,www.swift.com,www.cisco.com,www.asus.com,www.samsung.com,www.amd.com,www.fom-international.com,github.io"
    if [[ -n "${realityServerName}" && -z "${lastInstallationConfig}" ]]; then
        if echo ${realityDestDomainList} | grep -q "${realityServerName}"; then
            read -r -p "读取到上次安装设置的Reality域名，是否使用？[y/n]:" realityServerNameStatus
            if [[ "${realityServerNameStatus}" != "y" ]]; then
                realityServerName=
                realityDomainPort=
            fi
        else
            realityServerName=
            realityDomainPort=
        fi
    elif [[ -n "${realityServerName}" && -z "${lastInstallationConfig}" ]]; then
        realityServerName=
        realityDomainPort=
    fi

    if [[ -z "${realityServerName}" ]]; then
        if [[ -n "${domain}" ]]; then
            echo
            read -r -p "是否使用 ${domain} 此域名作为Reality目标域名 ？[y/n]:" realityServerNameCurrentDomainStatus
            if [[ "${realityServerNameCurrentDomainStatus}" == "y" ]]; then
                realityServerName="${domain}"
                if [[ -z "${subscribePort}" ]]; then
                    echo
                    installSubscribe
                    readNginxSubscribe
                    realityDomainPort="${subscribePort}"
                else
                    realityDomainPort="${subscribePort}"
                fi
            fi
        fi
        if [[ -z "${realityServerName}" ]]; then
            realityDomainPort=443
            echoContent skyBlue "\n================ 配置客户端可用的serverNames ===============\n"
            echoContent yellow "#注意事项"
            echoContent green "Reality目标可用域名列表：https://www.v2ray-agent.com/archives/1689439383686#heading-3\n"
            echoContent yellow "录入示例:addons.mozilla.org:443\n"
            read -r -p "请输入目标域名，[回车]随机域名，默认端口443:" realityServerName
            if [[ -z "${realityServerName}" ]]; then
                count=$(echo ${realityDestDomainList} | awk -F',' '{print NF}')
                randomNum=$(randomNum 1 "${count}")

                realityServerName=$(echo "${realityDestDomainList}" | awk -F ',' -v randomNum="$randomNum" '{print $randomNum}')
            fi
            if echo "${realityServerName}" | grep -q ":"; then
                realityDomainPort=$(echo "${realityServerName}" | awk -F "[:]" '{print $2}')
                realityServerName=$(echo "${realityServerName}" | awk -F "[:]" '{print $1}')
            fi
        fi
    fi

    echoContent yellow "\n ---> 客户端可用域名: ${realityServerName}:${realityDomainPort}\n"
}
# reality管理
manageReality() {
    readInstallProtocolType
    readConfigHostPathUUID
    readCustomPort
    readSingBoxConfig

    if ! echo "${currentInstallProtocolType}" | grep -q -E "7,|8," || [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n ---> 请先安装Reality协议"
        exit 0
    fi

    if echo "${currentInstallProtocolType}" | grep -q ",7,"; then
        selectCustomInstallType=",7,"
    fi
    if echo "${currentInstallProtocolType}" | grep -q ",8,"; then
        selectCustomInstallType="${selectCustomInstallType},8,"
    fi
    initSingBoxConfig custom 1 true

    reloadCore
    subscribe false
}

manageHysteria() {
    echoContent skyBlue "\n进度  1/1 : Hysteria2 管理"
    echoContent red "\n=============================================================="
    local hysteria2Status=
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json" ]]; then
        echoContent yellow "依赖第三方sing-box\n"
        echoContent yellow "1.重新安装"
        echoContent yellow "2.卸载"
        echoContent yellow "3.端口跳跃管理"
        hysteria2Status=true
    else
        echoContent yellow "依赖sing-box内核\n"
        echoContent yellow "1.安装"
    fi

    echoContent red "=============================================================="
    read -r -p "请选择:" installHysteria2Status
    if [[ "${installHysteria2Status}" == "1" ]]; then
        singBoxHysteria2Install
    elif [[ "${installHysteria2Status}" == "2" && "${hysteria2Status}" == "true" ]]; then
        unInstallSingBox hysteria2
    elif [[ "${installHysteria2Status}" == "3" && "${hysteria2Status}" == "true" ]]; then
        portHoppingMenu hysteria2
    fi
}

# tuic管理
manageTuic() {
    echoContent skyBlue "\n进度  1/1 : Tuic管理"
    echoContent red "\n=============================================================="
    local tuicStatus=
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json" ]]; then
        echoContent yellow "依赖sing-box内核\n"
        echoContent yellow "1.重新安装"
        echoContent yellow "2.卸载"
        echoContent yellow "3.端口跳跃管理"
        tuicStatus=true
    else
        echoContent yellow "依赖sing-box内核\n"
        echoContent yellow "1.安装"
    fi

    echoContent red "=============================================================="
    read -r -p "请选择:" installTuicStatus
    if [[ "${installTuicStatus}" == "1" ]]; then
        singBoxTuicInstall
    elif [[ "${installTuicStatus}" == "2" && "${tuicStatus}" == "true" ]]; then
        unInstallSingBox tuic
    elif [[ "${installTuicStatus}" == "3" && "${tuicStatus}" == "true" ]]; then
        portHoppingMenu tuic
    fi
}
# sing-box log日志
singBoxLog() {
    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/log.json
{
  "log": {
    "disabled": $1,
    "level": "debug",
    "output": "/etc/v2ray-agent/sing-box/conf/box.log",
    "timestamp": true
  }
}
EOF

    handleSingBox stop
    handleSingBox start
}

# sing-box 版本管理
singBoxVersionManageMenu() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : sing-box 版本管理"
    if [[ -z "${singBoxConfigPath}" ]]; then
        echoContent red " ---> 没有检测到安装程序，请执行脚本安装内容"
        menu
        exit 0
    fi
    echoContent red "\n=============================================================="
    echoContent yellow "1.升级 sing-box"
    echoContent yellow "2.关闭 sing-box"
    echoContent yellow "3.打开 sing-box"
    echoContent yellow "4.重启 sing-box"
    echoContent yellow "=============================================================="
    local logStatus=
    if [[ -n "${singBoxConfigPath}" && -f "${singBoxConfigPath}log.json" && "$(jq -r .log.disabled "${singBoxConfigPath}log.json")" == "false" ]]; then
        echoContent yellow "5.关闭日志"
        logStatus=true
    else
        echoContent yellow "5.启用日志"
        logStatus=false
    fi

    echoContent yellow "6.查看日志"
    echoContent red "=============================================================="

    read -r -p "请选择:" selectSingBoxType
    if [[ ! -f "${singBoxConfigPath}../box.log" ]]; then
        touch "${singBoxConfigPath}../box.log" >/dev/null 2>&1
    fi
    if [[ "${selectSingBoxType}" == "1" ]]; then
        installSingBox 1
        handleSingBox stop
        handleSingBox start
    elif [[ "${selectSingBoxType}" == "2" ]]; then
        handleSingBox stop
    elif [[ "${selectSingBoxType}" == "3" ]]; then
        handleSingBox start
    elif [[ "${selectSingBoxType}" == "4" ]]; then
        handleSingBox stop
        handleSingBox start
    elif [[ "${selectSingBoxType}" == "5" ]]; then
        singBoxLog ${logStatus}
        if [[ "${logStatus}" == "false" ]]; then
            tail -f "${singBoxConfigPath}../box.log"
        fi
    elif [[ "${selectSingBoxType}" == "6" ]]; then
        tail -f "${singBoxConfigPath}../box.log"
    fi
}

# 主菜单
menu() {
    cd "$HOME" || exit
    echoContent red "\n=============================================================="
    echoContent green "作者：mack-a (精简版)"
    echoContent green "当前版本：v3.5.5-singbox"
    echoContent green "Github：https://github.com/mack-a/v2ray-agent"
    echoContent green "描述：sing-box 多协议脚本\c"
    showInstallStatus
    checkWgetShowProgress
    echoContent red "\n=========================== 推广区============================"
    echoContent red "                                              "
    echoContent yellow "VPS选购攻略"
    echoContent green "https://www.v2ray-agent.com/archives/1679975663984"
    echoContent yellow "年付10美金低价VPS AS4837"
    echoContent green "https://www.v2ray-agent.com/archives/racknerdtao-can-zheng-li-nian-fu-10mei-yuan"
    echoContent yellow "优质常驻套餐DMIT CN2-GIA"
    echoContent green "https://www.v2ray-agent.com/archives/186cee7b-9459-4e57-b9b2-b07a4f36931c"
    echoContent yellow "VPS探针：https://ping.v2ray-agent.com/"
    echoContent red "                                              "
    echoContent red "=============================================================="
    if [[ -n "${coreInstallType}" ]]; then
        echoContent yellow "1.重新安装"
    else
        echoContent yellow "1.安装"
    fi

    echoContent yellow "2.任意组合安装"
    echoContent yellow "4.Hysteria2管理"
    echoContent yellow "5.REALITY管理"
    echoContent yellow "6.Tuic管理"

    echoContent skyBlue "-------------------------工具管理-----------------------------"
    echoContent yellow "7.用户管理"
    echoContent yellow "8.伪装站管理"
    echoContent yellow "9.证书管理"
    echoContent yellow "10.CDN节点管理"
    echoContent yellow "11.分流工具"
    echoContent skyBlue "-------------------------版本管理-----------------------------"
    echoContent yellow "16.core管理"
    echoContent yellow "17.更新脚本"
    echoContent yellow "18.安装BBR、DD脚本"
    echoContent skyBlue "-------------------------脚本管理-----------------------------"
    echoContent yellow "20.卸载脚本"
    echoContent red "=============================================================="
    mkdirTools
    aliasInstall
    read -r -p "请选择:" selectInstallType
    case ${selectInstallType} in
    1)
        selectCoreInstall
        ;;
    2)
        selectCoreInstall
        ;;
    4)
        manageHysteria
        ;;
    5)
        manageReality 1
        ;;
    6)
        manageTuic
        ;;
    7)
        manageAccount 1
        ;;
    8)
        updateNginxBlog 1
        ;;
    9)
        renewalTLS 1
        ;;
    10)
        manageCDN 1
        ;;
    11)
        inboundRoutingMenu 1
        ;;
    16)
        coreVersionManageMenu 1
        ;;
    17)
        updateV2RayAgent 1
        ;;
    18)
        bbrInstall
        ;;
    20)
        unInstall 1
        ;;
    esac
}
cronFunction
menu
