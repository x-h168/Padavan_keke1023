#!/bin/sh

result=0
mtd_part_name="Storage"
mtd_part_dev="/dev/mtdblock5"
mtd_part_size=1024000
dir_storage="/etc/storage"
slk="/tmp/.storage_locked"
tmp="/tmp/storage.tar"
tbz="${tmp}.bz2"
hsh="/tmp/hashes/storage_md5"

ap_script="/etc/storage/ap_script.sh"


func_get_mtd()
{
	local mtd_part mtd_char mtd_idx mtd_hex
	mtd_part=`cat /proc/mtd | grep \"$mtd_part_name\"`
	mtd_char=`echo $mtd_part | cut -d':' -f1`
	mtd_hex=`echo $mtd_part | cut -d' ' -f2`
	mtd_idx=`echo $mtd_char | cut -c4-5`
	if [ -n "$mtd_idx" ] && [ $mtd_idx -ge 4 ] ; then
		mtd_part_dev="/dev/mtdblock${mtd_idx}"
		mtd_part_size=`echo $((0x$mtd_hex))`
	else
		logger -t "Storage" "Cannot find MTD partition: $mtd_part_name"
		exit 1
	fi
}

func_mdir()
{
	[ ! -d "$dir_storage" ] && mkdir -p -m 755 $dir_storage
}

func_stop_apps()
{
	killall -q rstats
	[ $? -eq 0 ] && sleep 1
}

func_start_apps()
{
	/sbin/rstats
}

func_load()
{
	local fsz

	bzcat $mtd_part_dev > $tmp 2>/dev/null
	fsz=`stat -c %s $tmp 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -gt 0 ] ; then
		md5sum $tmp > $hsh
		tar xf $tmp -C $dir_storage 2>/dev/null
	else
		result=1
		rm -f $hsh
		logger -t "Storage load" "Invalid storage data in MTD partition: $mtd_part_dev"
	fi
	rm -f $tmp
	rm -f $slk
}

func_tarb()
{
	rm -f $tmp
	cd $dir_storage
	find * -print0 | xargs -0 touch -c -h -t 201001010000.00
	find * ! -type d -print0 | sort -z | xargs -0 tar -cf $tmp 2>/dev/null
	cd - >>/dev/null
	if [ ! -f "$tmp" ] ; then
		logger -t "Storage" "Cannot create tarball file: $tmp"
		exit 1
	fi
}

func_save()
{
	local fsz

	logger -t "Storage save" "Save storage files to MTD partition \"$mtd_part_dev\""
	echo "Save storage files to MTD partition \"$mtd_part_dev\""
	rm -f $tbz
	md5sum -c -s $hsh 2>/dev/null
	if [ $? -eq 0 ] ; then
		echo "Storage hash is not changed, skip write to MTD partition. Exit."
		rm -f $tmp
		return 0
	fi
	md5sum $tmp > $hsh
	bzip2 -9 $tmp 2>/dev/null
	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -ge 16 ] && [ $fsz -le $mtd_part_size ] ; then
		mtd_write write $tbz $mtd_part_name
		if [ $? -eq 0 ] ; then
			echo "Done."
			logger -t "Storage save" "Done."
		else
			result=1
			echo "Error! MTD write FAILED"
			logger -t "Storage save" "Error write to MTD partition: $mtd_part_dev"
		fi
	else
		result=1
		echo "Error! Invalid storage final data size: $fsz"
		logger -t "Storage save" "Invalid storage final data size: $fsz"
	fi
	rm -f $tmp
	rm -f $tbz
}

func_backup()
{
	rm -f $tbz
	bzip2 -9 $tmp 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		logger -t "Storage backup" "Cannot create BZ2 file!"
	fi
	rm -f $tmp
}

func_restore()
{
	local fsz tmp_storage

	[ ! -f "$tbz" ] && exit 1

	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -z "$fsz" ] || [ $fsz -lt 16 ] || [ $fsz -gt $mtd_part_size ] ; then
		result=1
		rm -f $tbz
		logger -t "Storage restore" "Invalid BZ2 file size: $fsz"
		return 1
	fi

	tmp_storage="/tmp/storage"
	rm -rf $tmp_storage
	mkdir -p -m 755 $tmp_storage
	tar xjf $tbz -C $tmp_storage 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Unable to extract BZ2 file: $tbz"
		return 1
	fi
	if [ ! -f "$tmp_storage/start_script.sh" ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Invalid content of BZ2 file: $tbz"
		return 1
	fi

	func_stop_apps

	rm -f $slk
	rm -f $tbz
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
	cp -rf $tmp_storage /etc
	rm -rf $tmp_storage

	func_start_apps
}

func_erase()
{
	mtd_write erase $mtd_part_name
	if [ $? -eq 0 ] ; then
		rm -f $hsh
		rm -rf $dir_storage
		mkdir -p -m 755 $dir_storage
		touch "$slk"
	else
		result=1
	fi
}

func_reset()
{
	rm -f $slk
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
}

func_fill()
{
	dir_httpssl="$dir_storage/https"
	dir_dnsmasq="$dir_storage/dnsmasq"
	dir_ovpnsvr="$dir_storage/openvpn/server"
	dir_ovpncli="$dir_storage/openvpn/client"
	dir_sswan="$dir_storage/strongswan"
	dir_sswan_crt="$dir_sswan/ipsec.d"
	dir_inadyn="$dir_storage/inadyn"
	dir_crond="$dir_storage/cron/crontabs"
	dir_wlan="$dir_storage/wlan"
	dir_chnroute="$dir_storage/chinadns"
	#dir_gfwlist="$dir_storage/gfwlist"

	script_start="$dir_storage/start_script.sh"
	script_started="$dir_storage/started_script.sh"
	script_shutd="$dir_storage/shutdown_script.sh"
	script_postf="$dir_storage/post_iptables_script.sh"
	script_postw="$dir_storage/post_wan_script.sh"
	script_inets="$dir_storage/inet_state_script.sh"
	script_vpnsc="$dir_storage/vpns_client_script.sh"
	script_vpncs="$dir_storage/vpnc_server_script.sh"
	script_ezbtn="$dir_storage/ez_buttons_script.sh"

	user_hosts="$dir_dnsmasq/hosts"
	user_dnsmasq_conf="$dir_dnsmasq/dnsmasq.conf"
	user_dhcp_conf="$dir_dnsmasq/dhcp.conf"
	user_ovpnsvr_conf="$dir_ovpnsvr/server.conf"
	user_ovpncli_conf="$dir_ovpncli/client.conf"
	user_inadyn_conf="$dir_inadyn/inadyn.conf"
	user_sswan_conf="$dir_sswan/strongswan.conf"
	user_sswan_ipsec_conf="$dir_sswan/ipsec.conf"
	user_sswan_secrets="$dir_sswan/ipsec.secrets"
	
	chnroute_file="/etc_ro/chnroute.bz2"
	#gfwlist_conf_file="/etc_ro/gfwlist.bz2"

	# create crond dir
	[ ! -d "$dir_crond" ] && mkdir -p -m 730 "$dir_crond"

	# create https dir
	[ ! -d "$dir_httpssl" ] && mkdir -p -m 700 "$dir_httpssl"

	# create chnroute.txt
	if [ ! -d "$dir_chnroute" ] ; then
		if [ -f "$chnroute_file" ]; then
			mkdir -p "$dir_chnroute" && tar jxf "$chnroute_file" -C "$dir_chnroute"
		fi
	fi

	# create gfwlist
	#if [ ! -d "$dir_gfwlist" ] ; then
	#	if [ -f "$gfwlist_conf_file" ]; then	
	#		mkdir -p "$dir_gfwlist" && tar jxf "$gfwlist_conf_file" -C "$dir_gfwlist"
	#	fi
	#fi

	# create start script
	if [ ! -f "$script_start" ] ; then
		reset_ss.sh -a
	fi

	# create started script
	if [ ! -f "$script_started" ] ; then
		cat > "$script_started" <<'EOF'

###########################################################################
	if [ ! -f "$ap_script" ] || [ ! -s "$ap_script" ] ; then
	cat > "$ap_script" <<-\EEE
#!/bin/sh
#/etc/storage/ap_script.sh
#copyright by hiboy

# AP中继连接守护功能。【0】 Internet互联网断线后自动搜寻；【1】 当中继信号断开时启动自动搜寻。
nvram set ap_check=0

# AP连接成功条件，【0】 连上AP即可，不检查是否联网；【1】 连上AP并连上Internet互联网。
nvram set ap_inet_check=0

# 【0】 自动搜寻AP，成功连接后停止搜寻；大于等于【10】时则每隔【N】秒搜寻(无线网络会瞬断一下)，直到连上最优先信号。
nvram set ap_time_check=0

# 如搜寻的AP不联网则列入黑名单/tmp/apblack.txt 功能 【0】关闭；【1】启动
# 控制台输入【echo "" > /tmp/apblack.txt】可以清空黑名单
nvram set ap_black=0

# 自定义分隔符号，默认为【@】，注意:下面配置一同修改
nvram set ap_fenge='@'

# 搜寻AP排序设置【0】从第一行开始（第一行的是最优先信号）；【1】不分顺序自动连接最强信号
nvram set ap_rule=0

# 【自动切换中继信号】功能 填写配置参数启动
cat >/tmp/ap2g5g.txt <<-\EOF
# 中继AP配置填写说明：
# 各参数用【@】分割开，如果有多个信号可回车换行继续填写即可(从第一行的参数开始搜寻)【第一行的是最优先信号】
# 搜寻时无线网络会瞬断一下
# 参数说明：
# ①2.4Ghz或5Ghz："2"=【2.4Ghz】"5"=【5Ghz】
# ②无线AP工作模式："0"=【AP（桥接被禁用）】"3"=【AP-Client（AP被禁用）】"4"=【AP-Client + AP】（不支持WDS）
# ③无线AP-Client角色： "0"=【LAN bridge】"1"=【WAN (Wireless ISP)】
# ④中继AP 的 SSID："ASUS"
# ⑤中继AP 密码："1234567890"
# ⑥中继AP 的 MAC地址："20:76:90:20:B0:F0"【SSID有中文时需填写，不限大小写】
# 下面是信号填写例子：（删除前面的#可生效）
#2@4@1@ASUS@1234567890
#2@4@1@ASUS_中文@1234567890@34:bd:f9:1f:d2:b1
#2@4@1@ASUS3@1234567890@34:bd:f9:1f:d2:b0

EOF
cat /tmp/ap2g5g.txt | grep -v '^#'  | grep -v "^$" > /tmp/ap2g5g
killall sh_apauto.sh
if [ -s /tmp/ap2g5g ] ; then
cat >/tmp/sh_apauto.sh <<-\EOF
#!/bin/sh
[ "$1" = "crontabs" ] && sleep 15
logger -t "【AP 中继】" "连接守护启动"
while [ -s /tmp/ap2g5g ]; do
radio2_apcli=`nvram get radio2_apcli`
[ -z $radio2_apcli ] && radio2_apcli="apcli0"
radio5_apcli=`nvram get radio5_apcli`
[ -z $radio5_apcli ] && radio5_apcli="apclii0"
  ap_check=`nvram get ap_check`
  if [[ "$ap_check" == 1 ]] && [ ! -f /tmp/apc.lock ] ; then
  #【1】 当中继信号断开时启动自动搜寻
  a2=`iwconfig $radio2_apcli | awk -F'"' '/ESSID/ {print $2}'`
  sleep 1
  a5=`iwconfig $radio5_apcli | awk -F'"' '/ESSID/ {print $2}'`
  sleep 1
  [ "$a2" = "" -a "$a5" = "" ] && ap=1 || ap=0
  if [ "$ap" = "1" ] ; then
    logger -t "【AP 中继】" "连接中断，启动自动搜寻"
    sh_ezscript.sh connAPSite_scan &
    sleep 10
  fi
  fi
  ap_time_check="$(nvram get ap_time_check)"
  if [ "$ap_time_check" -ge 9 ] && [ ! -f /tmp/apc.lock ] ; then
    ap_fenge="$(nvram get ap_fenge)"
    rtwlt_sta_ssid_1=$(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $ap_fenge -f4)
    rtwlt_sta_bssid_1=$(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $ap_fenge -f6 | tr 'A-Z' 'a-z')
    [ "$(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $ap_fenge -f1)" = "5" ] && radio2_apcli="$radio5_apcli"
    rtwlt_sta_ssid="$(iwconfig $radio2_apcli | grep ESSID: | awk -F'"' '/ESSID/ {print $2}')"
    sleep 1
    rtwlt_sta_bssid="$(iwconfig $radio2_apcli |sed -n '/'$radio2_apcli'/,/Rate/{/'$radio2_apcli'/n;/Rate/b;p}' | tr 'A-Z' 'a-z'  | awk -F'point:' '/point/ {print $2}')"
    sleep 1
    rtwlt_sta_bssid="$(echo $rtwlt_sta_bssid)"
    [ ! -z "$rtwlt_sta_ssid_1" ] && [ ! -z "$rtwlt_sta_ssid" ] && [ "$rtwlt_sta_ssid_1" == "$rtwlt_sta_ssid" ] && ap_time_check=0
    [ ! -z "$rtwlt_sta_bssid_1" ] && [ ! -z "$rtwlt_sta_bssid" ] && [ "$rtwlt_sta_bssid_1" == "$rtwlt_sta_bssid" ] && ap_time_check=0
    if [ "$ap_time_check" -ge 9 ] && [ ! -f /tmp/apc.lock ] ; then
    logger -t "【连接 AP】" "$ap_time_check 秒后,自动搜寻 ap ,直到连上最优先信号 $rtwlt_sta_ssid_1 "
    sleep $ap_time_check
    sh_ezscript.sh connAPSite_scan &
    sleep 10
    fi
  fi
  if [[ "$ap_check" == 0 ]] && [ ! -f /tmp/apc.lock ] ; then
    #【2】 Internet互联网断线后自动搜寻
    ping_text=`ping -4 223.5.5.5 -c 1 -w 4 -q`
    ping_time=`echo $ping_text | awk -F '/' '{print $4}'| awk -F '.' '{print $1}'`
    ping_loss=`echo $ping_text | awk -F ', ' '{print $3}' | awk '{print $1}'`
    if [ ! -z "$ping_time" ] ; then
    echo "online"
    else
    echo "Internet互联网断线后自动搜寻"
    sh_ezscript.sh connAPSite_scan &
    sleep 10
    fi
  fi
  sleep 63
  cat /tmp/ap2g5g.txt | grep -v '^#'  | grep -v "^$" > /tmp/ap2g5g
done
EOF
  chmod 777 "/tmp/sh_apauto.sh"
  [ -z "$(ps -w | grep sh_apauto.sh | grep -v grep)" ] && /tmp/sh_apauto.sh $1 &
fi

EEE
		chmod 755 "$ap_script"
	fi

#################################################################################


  
#!/bin/sh

### Custom user script
### Called after router started and network is ready

### Example - load ipset modules
#modprobe ip_set
#modprobe ip_set_hash_ip
#modprobe ip_set_hash_net
#modprobe ip_set_bitmap_ip
#modprobe ip_set_list_set
#modprobe xt_set
echo 4096 131072  6291456 > /proc/sys/net/ipv4/tcp_rmem
echo 4194304 >/proc/sys/net/core/rmem_max
echo 212992 > /proc/sys/net/core/rmem_default

#drop caches
sync && echo 3 > /proc/sys/vm/drop_caches

# Roaming assistant for mt76xx WiFi
#iwpriv ra0 set KickStaRssiLow=-85
#iwpriv ra0 set AssocReqRssiThres=-80
#iwpriv rai0 set KickStaRssiLow=-85
#iwpriv rai0 set AssocReqRssiThres=-80
>>>>>>> a321e6940bb0cb44619e21b8b3df6e91f892751a

# Mount SATA disk
#mdev -s

#wing <HOST:443> <PASS>
#wing 192.168.1.9:1080
#ipset add gfwlist 8.8.4.4


EOF
		chmod 755 "$script_started"
	fi

	# create shutdown script
	if [ ! -f "$script_shutd" ] ; then
		cat > "$script_shutd" <<EOF
#!/bin/sh

### Custom user script
### Called before router shutdown
### \$1 - action (0: reboot, 1: halt, 2: power-off)

EOF
		chmod 755 "$script_shutd"
	fi

	# create post-iptables script

	if [ ! -f "$script_postf" ] ; then
		cat > "$script_postf" <<EOF
#!/bin/sh

### Custom user script
### Called after internal iptables reconfig (firewall update)

#wing resume

EOF
		chmod 755 "$script_postf"
	fi

	# create post-wan script
	if [ ! -f "$script_postw" ] ; then
		cat > "$script_postw" <<EOF
#!/bin/sh

### Custom user script
### Called after internal WAN up/down action
### \$1 - WAN action (up/down)
### \$2 - WAN interface name (e.g. eth3 or ppp0)
### \$3 - WAN IPv4 address

EOF
		chmod 755 "$script_postw"
	fi

	# create inet-state script
	if [ ! -f "$script_inets" ] ; then
		cat > "$script_inets" <<EOF
#!/bin/sh

### Custom user script
### Called on Internet status changed
### \$1 - Internet status (0/1)
### \$2 - elapsed time (s) from previous state

logger -t "di" "Internet state: \$1, elapsed time: \$2s."

EOF
		chmod 755 "$script_inets"
	fi

	# create vpn server action script
	if [ ! -f "$script_vpnsc" ] ; then
		cat > "$script_vpnsc" <<EOF
#!/bin/sh

### Custom user script
### Called after remote peer connected/disconnected to internal VPN server
### \$1 - peer action (up/down)
### \$2 - peer interface name (e.g. ppp10)
### \$3 - peer local IP address
### \$4 - peer remote IP address
### \$5 - peer name

peer_if="\$2"
peer_ip="\$4"
peer_name="\$5"

### example: add static route to private LAN subnet behind a remote peer

func_ipup()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route add -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route add -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

func_ipdown()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route del -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route del -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpnsc"
	fi

	# create vpn client action script
	if [ ! -f "$script_vpncs" ] ; then
		cat > "$script_vpncs" <<EOF
#!/bin/sh

### Custom user script
### Called after internal VPN client connected/disconnected to remote VPN server
### \$1        - action (up/down)
### \$IFNAME   - tunnel interface name (e.g. ppp5 or tun0)
### \$IPLOCAL  - tunnel local IP address
### \$IPREMOTE - tunnel remote IP address
### \$DNS1     - peer DNS1
### \$DNS2     - peer DNS2

# private LAN subnet behind a remote server (example)
peer_lan="192.168.9.0"
peer_msk="255.255.255.0"

### example: add static route to private LAN subnet behind a remote server

func_ipup()
{
#  route add -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

func_ipdown()
{
#  route del -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

logger -t vpnc-script "\$IFNAME \$1"

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpncs"
	fi

	# create Ez-Buttons script
	if [ ! -f "$script_ezbtn" ] ; then
		cat > "$script_ezbtn" <<EOF
#!/bin/sh

### Custom user script
### Called on WPS or FN button pressed
### \$1 - button param

[ -x /opt/bin/on_wps.sh ] && /opt/bin/on_wps.sh \$1 &

EOF
		chmod 755 "$script_ezbtn"
	fi

	# create user dnsmasq.conf
	[ ! -d "$dir_dnsmasq" ] && mkdir -p -m 755 "$dir_dnsmasq"
	for i in dnsmasq.conf hosts ; do
		[ -f "$dir_storage/$i" ] && mv -n "$dir_storage/$i" "$dir_dnsmasq"
	done
	if [ ! -f "$user_dnsmasq_conf" ] ; then
		cat > "$user_dnsmasq_conf" <<EOF
# Custom user conf file for dnsmasq
# Please add needed params only!

### Web Proxy Automatic Discovery (WPAD)
dhcp-option=252,"\n"

### Set the limit on DHCP leases, the default is 150
#dhcp-lease-max=150

### Add local-only domains, queries are answered from hosts or DHCP only
#local=/router/localdomain/

### Examples:

### Enable built-in TFTP server
#enable-tftp

### Set the root directory for files available via TFTP.
#tftp-root=/opt/srv/tftp

### Make the TFTP server more secure
#tftp-secure

### Set the boot filename for netboot/PXE
#dhcp-boot=pxelinux.0

### Log for all queries
#log-queries

### Keep DHCP host name valid at any times
#dhcp-to-host

EOF
	if [ -f /usr/bin/vlmcsd ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### vlmcsd related
srv-host=_vlmcs._tcp,my.router,1688,0,100

EOF
	fi

	if [ -f /usr/bin/wing ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
# Custom domains to gfwlist
#gfwlist=mit.edu
#gfwlist=openwrt.org,lede-project.org
#gfwlist=github.com,github.io,githubusercontent.com

EOF
	fi

	if [ -d $dir_gfwlist ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### gfwlist related (resolve by port 5353)
#min-cache-ttl=3600
#conf-dir=/etc/storage/gfwlist

EOF
	fi
		chmod 644 "$user_dnsmasq_conf"
	fi

	# create user dns servers
	if [ ! -f "$user_dhcp_conf" ] ; then
		cat > "$user_dhcp_conf" <<EOF
#6C:96:CF:E0:95:55,192.168.1.10,iMac

EOF
		chmod 644 "$user_dhcp_conf"
	fi

	# create user inadyn.conf"
	[ ! -d "$dir_inadyn" ] && mkdir -p -m 755 "$dir_inadyn"
	if [ ! -f "$user_inadyn_conf" ] ; then
		cat > "$user_inadyn_conf" <<EOF
# Custom user conf file for inadyn DDNS client
# Please add only new custom system!

### Example for twoDNS.de:

#system custom@http_srv_basic_auth
#  ssl
#  checkip-url checkip.two-dns.de /
#  server-name update.twodns.de
#  server-url /update\?hostname=
#  username account
#  password secret
#  alias example.dd-dns.de

EOF
		chmod 644 "$user_inadyn_conf"
	fi

	# create user hosts
	if [ ! -f "$user_hosts" ] ; then
		cat > "$user_hosts" <<EOF
# Custom user hosts file
# Example:
# 192.168.1.100		Boo

EOF
		chmod 644 "$user_hosts"
	fi

	# create user AP confs
	[ ! -d "$dir_wlan" ] && mkdir -p -m 755 "$dir_wlan"
	if [ ! -f "$dir_wlan/AP.dat" ] ; then
		cat > "$dir_wlan/AP.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP.dat"
	fi

	if [ ! -f "$dir_wlan/AP_5G.dat" ] ; then
		cat > "$dir_wlan/AP_5G.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP_5G.dat"
	fi

	# create openvpn files
	if [ -x /usr/sbin/openvpn ] ; then
		[ ! -d "$dir_ovpncli" ] && mkdir -p -m 700 "$dir_ovpncli"
		[ ! -d "$dir_ovpnsvr" ] && mkdir -p -m 700 "$dir_ovpnsvr"
		dir_ovpn="$dir_storage/openvpn"
		for i in ca.crt dh1024.pem server.crt server.key server.conf ta.key ; do
			[ -f "$dir_ovpn/$i" ] && mv -n "$dir_ovpn/$i" "$dir_ovpnsvr"
		done
		if [ ! -f "$user_ovpnsvr_conf" ] ; then
			cat > "$user_ovpnsvr_conf" <<EOF
# Custom user conf file for OpenVPN server
# Please add needed params only!

### Max clients limit
max-clients 10

### Internally route client-to-client traffic
client-to-client

### Allow clients with duplicate "Common Name"
;duplicate-cn

### Legacy LZO adaptive compression
;comp-lzo adaptive
;push "comp-lzo adaptive"

### Keepalive and timeout
keepalive 10 60

### Process priority level (0..19)
nice 3

### Syslog verbose level
verb 0
mute 10

EOF
			chmod 644 "$user_ovpnsvr_conf"
		fi

		if [ ! -f "$user_ovpncli_conf" ] ; then
			cat > "$user_ovpncli_conf" <<EOF
# Custom user conf file for OpenVPN client
# Please add needed params only!

### If your server certificates with the nsCertType field set to "server"
remote-cert-tls server

### Process priority level (0..19)
nice 0

### Syslog verbose level
verb 0
mute 10

EOF
			chmod 644 "$user_ovpncli_conf"
		fi
	fi

	# create strongswan files
	if [ -x /usr/sbin/ipsec ] ; then
		[ ! -d "$dir_sswan" ] && mkdir -p -m 700 "$dir_sswan"
		[ ! -d "$dir_sswan_crt" ] && mkdir -p -m 700 "$dir_sswan_crt"
		[ ! -d "$dir_sswan_crt/cacerts" ] && mkdir -p -m 700 "$dir_sswan_crt/cacerts"
		[ ! -d "$dir_sswan_crt/certs" ] && mkdir -p -m 700 "$dir_sswan_crt/certs"
		[ ! -d "$dir_sswan_crt/private" ] && mkdir -p -m 700 "$dir_sswan_crt/private"

		if [ ! -f "$user_sswan_conf" ] ; then
			cat > "$user_sswan_conf" <<EOF
### strongswan.conf - user strongswan configuration file

EOF
			chmod 644 "$user_sswan_conf"
		fi
		if [ ! -f "$user_sswan_ipsec_conf" ] ; then
			cat > "$user_sswan_ipsec_conf" <<EOF
### ipsec.conf - user strongswan IPsec configuration file

EOF
			chmod 644 "$user_sswan_ipsec_conf"
		fi
		if [ ! -f "$user_sswan_secrets" ] ; then
			cat > "$user_sswan_secrets" <<EOF
### ipsec.secrets - user strongswan IPsec secrets file

EOF
			chmod 644 "$user_sswan_secrets"
		fi
	fi
}

case "$1" in
load)
	func_get_mtd
	func_mdir
	func_load
	;;
save)
	[ -f "$slk" ] && exit 1
	func_get_mtd
	func_mdir
	func_tarb
	func_save
	;;
backup)
	func_mdir
	func_tarb
	func_backup
	;;
restore)
	func_get_mtd
	func_restore
	;;
erase)
	func_get_mtd
	func_erase
	;;
reset)
	func_stop_apps
	func_reset
	func_fill
	func_start_apps
	;;
fill)
	func_mdir
	func_fill
	;;
*)
	echo "Usage: $0 {load|save|backup|restore|erase|reset|fill}"
	exit 1
	;;
esac

exit $result
