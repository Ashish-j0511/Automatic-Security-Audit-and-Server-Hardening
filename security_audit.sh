#!/bin/bash

# Create output directory if it doesn't exist
if [ ! -d "output" ]; then
    mkdir output
    echo "Created 'output' directory."
fi


# Set the report file path
REPORT_FILE="output/audit_report_$(date +%F_%T).txt"

generate_header() {
    local hostname=$(hostname)
    local current_date=$(date '+%Y-%m-%d')

    {
        echo "#######################################################################"
        echo "#  Security Audit Report for: $hostname                        "
        echo "#  Date: $current_date                                         "
        echo "#######################################################################"
        echo
    } >> "$REPORT_FILE"
}

audit_user_group() {
    {
        echo "------------------------------------------------------------------------"
        echo "========================= User and Group Audits ========================"
        echo "------------------------------------------------------------------------"
        echo 
        # Total users and groups
        all_users=$(awk -F: '{print $1}' /etc/passwd )

        echo "• All Users :"
        echo "-----------------------------------------------------------------------"
        echo "$all_users"
        total_users=$(awk -F: '{print $1}' /etc/passwd | wc -l)
        echo " - Total users: $total_users"

        echo 

        all_groups=$(awk -F: '{print $1}' /etc/group)
        echo "• All Groups :"
        echo "-----------------------------------------------------------------------"
        echo "$all_groups"
        total_groups=$(awk -F: '{print $1}' /etc/group | wc -l)
        echo " - Total groups: $total_groups"
        echo
        echo "-----------------------------------------------------------------------"
        

        # Users without passwords
        users_without_passwords=$(
            getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' | while read -r user; do
                passwd_status=$(passwd -S "$user" 2>/dev/null)
                if [[ $passwd_status == *"NP"* || $passwd_status == *"LK"* ]]; then
                    echo "$user"
                fi
            done
        )
        echo "• Users without passwords :"
        echo " - $users_without_passwords"


        # Users with UID 0
        echo
        user_uid=$(echo "• Users with UID 0 (should only be 'root'):"
        awk -F: '($3 == 0) { print " - " $1 }' /etc/passwd)


    } >> "$REPORT_FILE"
}

audit_permissions() {
    {
        echo "------------------------------------------------------------------------"
        echo "===================== File & Directory Permission ====================="
        echo "------------------------------------------------------------------------"
        echo
        
        echo "• All World-writable files and directories:"
        echo "-----------------------------------------------------------------------"

        all_world_writable_count=$(find / -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null)
        echo "$all_world_writable_count"
        echo
        world_writable_count=$(find / -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null | wc -l)
        echo " - Total World-writable files and directories: $world_writable_count"
        echo

        echo "• All .ssh Directory Permission Issues:"
        echo "-----------------------------------------------------------------------"
        ssh_count=0
        for home in $(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $6}'); do
            ssh_dir="$home/.ssh"
            if [ -d "$ssh_dir" ]; then
                perms=$(stat -c "%a" "$ssh_dir" 2>/dev/null)
                if [ "$perms" -ne 700 ]; then
                    echo " - $ssh_dir has wrong permissions: $perms"
                    ssh_count=$((ssh_count + 1))
                fi
            fi
        done
        echo " - Total .ssh directories with incorrect permissions: $ssh_count"
        echo

        echo "•All Files with SUID/SGID bits set:"
        echo "-----------------------------------------------------------------------"
        all_suid_sgid_count=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
        echo "$all_suid_sgid_count"
        suid_sgid_count=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l)
        echo " - Total Files with SUID/SGID bits set: $suid_sgid_count"
        echo


    } >> "$REPORT_FILE"
}

service_audit() {
    {
        echo "------------------------------------------------------------------------"
        echo "============================ Service Audits ============================"
        echo "------------------------------------------------------------------------"

        echo "•All Running services:"
        echo "-----------------------------------------------------------------------"

        echo
        running_count=$(systemctl list-units --type=service --state=running | grep '.service' )
        echo "$running_count"
        total_running_count=$(systemctl list-units --type=service --state=running | grep '.service' | wc -l )
        echo " - Total running services: $total_running_count"
        echo

        echo "• Critical services check:"

        critical_services=("sshd" "iptables" "httpd")
        for service in "${critical_services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                echo " - $service is running"
            else
                echo " - $service is NOT running"
            fi
        done


        echo
        echo "• Unauthorized or unnecessary services check:"

        unauthorized_services=("apache2" "nginx" "ftp" "telnet")
        found_unauthorized=0
        for service in "${unauthorized_services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                echo " - $service is running (should not be)"
                found_unauthorized=1
            fi
        done
        if [ "$found_unauthorized" -eq 0 ]; then
            echo " - None found"
        fi

        echo
        echo "• Services listening on non-standard or insecure ports:"

        insecure_ports=$(netstat -tuln | grep -E ":(21|23|25|110|143|3306|3389)")
        if [ -n "$insecure_ports" ]; then
            echo "$insecure_ports" | while read -r line; do
                echo " - $line"
            done
        else
            echo " - None found"
        fi
        echo
    } >> "$REPORT_FILE"
}

public_vs_private_ip_check() {
    {
        echo "------------------------------------------------------------------------"
        echo "===================== Firewall & Network Security ======================"
        echo "------------------------------------------------------------------------"

        echo "• IP Addresses Assigned to the Server:"
        ip addr show | grep -E "inet " | awk '{print $2}' | while read -r ip_address; do
            if echo "$ip_address" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])|^192\.168\."; then
                echo " - $ip_address (Private IP)"
            else
                echo " - $ip_address (Public IP)"
            fi
        done
        echo

        echo "• SSH Exposure on Public IP:"
        public_ips=$(ip addr show | grep -E "inet " | awk '{print $2}' | grep -vE "^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])|^192\.168\.")

        if [ -z "$public_ips" ]; then
            echo " - No public IP addresses found."
        else
            ssh_exposure="No"
            for public_ip in $public_ips; do
                if netstat -tuln | grep -q "$public_ip:22"; then
                    ssh_exposure="Yes"
                    echo " - SSH service is exposed on public IP $public_ip."
                fi
            done

            if [ "$ssh_exposure" == "No" ]; then
                echo " - SSH service is not exposed on public IPs."
            fi
        fi
        echo
    } >> "$REPORT_FILE"
}

check_updates() {
    {
        echo "------------------------------------------------------------------------"
        echo "===================== Security Updates & Patching ======================"
        echo "------------------------------------------------------------------------"
        echo "• Security Updates Status:"
        
        update_status="Unknown"

        if command -v yum &>/dev/null; then
            updates=$(yum check-update)
        elif command -v dnf &>/dev/null; then
            updates=$(dnf check-update)
        elif command -v apt &>/dev/null; then
            updates=$(apt update -qq && apt list --upgradable)
        else
            echo " - Package manager not recognized. Cannot check for updates."
            update_status="Unknown"
        fi

        if [ -n "$updates" ]; then
            echo " - Updates are available."
            update_status="Updates Available"
        else
            echo " - No updates available."
            update_status="No Updates"
        fi
        echo "$update_status"

        echo
    } >> "$REPORT_FILE"
}

log_monitoring() {
    {
        echo "------------------------------------------------------------------------"
        echo "============================ Log Monitoring ============================"
        echo "------------------------------------------------------------------------"
        failed_count=$(grep -c "Failed password" /var/log/secure 2>/dev/null)

        if [ "$failed_count" -gt 3 ]; then
            echo " - Multiple Failed SSH login attempts detected. Count: $failed_count"
        else
            echo " - No significant failed SSH login attempts found. Count: $failed_count"
        fi

        echo
    } >> "$REPORT_FILE"
}

server_hardening() {
    {
        echo "------------------------------------------------------------------------"
        echo "=========================== Server Hardening ==========================="
        echo "------------------------------------------------------------------------"
        echo "• SSH Configuration:"
        SSH_CONF="/etc/ssh/sshd_config"

        if grep -q "^PermitRootLogin yes" "$SSH_CONF"; then
            sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONF"
        fi

        if grep -q "^PasswordAuthentication yes" "$SSH_CONF"; then
            sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONF"
        fi

        echo " - Disabled root login and password authentication."
        systemctl restart sshd

        echo
        echo "• Disabling IPv6:"
        ip_6=$(CONFIG="/etc/sysctl.conf"
                if ! grep -q "disable_ipv6" "$CONFIG"; then
                    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> "$CONFIG"
                    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> "$CONFIG"
                    sysctl -p > /dev/null
                    echo " - IPv6 disabled system-wide."
                else
                    echo " - IPv6 already disabled."
                fi)
        echo "$ip_6"
        echo
        echo "• Configuring Basic Firewall Rules:"
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        echo " - Basic firewall rules configured (Only SSH allowed)."
        echo

        echo "• Automatic Updates Status:"
        auto_updates=$(if command -v dnf >/dev/null; then
                    dnf install -y dnf-automatic &>/dev/null && systemctl enable --now dnf-automatic.timer &>/dev/null
                    echo " - Automatic updates enabled using dnf-automatic."
                elif command -v yum >/dev/null; then
                    yum install -y yum-cron &>/dev/null && systemctl enable --now yum-cron &>/dev/null
                    echo " - Automatic updates enabled using yum-cron."
                elif command -v apt >/dev/null; then
                    apt install -y unattended-upgrades &>/dev/null && dpkg-reconfigure -plow unattended-upgrades &>/dev/null
                    echo " - Automatic updates enabled using unattended-upgrades."
                else
                    echo " - No supported package manager found."
                fi)
        echo "$auto_updates"
        echo 
    } >> "$REPORT_FILE"
}

audit_summaray () {
    echo "=========================== SUMMARY OF AUDIT REPORT ==========================="

    echo " - Total users: $total_users"

    echo " - Total groups: $total_groups"  

    printf "\e[31m - Users without passwords: %s\e[0m\n" "$user_without_passwords_count" "$users_without_passwords"


    printf "\e[31m - World-writable files found: %s\e[0m\n" "$world_writable_count"

    printf "\e[31m - Incorrect .ssh permissions for %s\e[0m\n" "$ssh_count"

    echo " - Total Services Running : $total_running_count"


    printf "\e[31m - Unauthorized services running: %s\e[0m\n" "$found_unauthorized"

    echo " - IPv6: $ip_6"

    printf "\e[31m - Security updates available: %s\e[0m\n" "$update_status"

    printf "\e[31m - Number of Failed SSH login attempts: %s\e[0m\n" "$failed_count"


    echo " - Firewall: Configured to allow $firewall_status "

    printf "\e[31m - Automatic updates: %s\e[0m\n" "$auto_updates"

    echo "============================================================================="

}



# Main Execution
generate_header
audit_user_group
audit_permissions
service_audit
public_vs_private_ip_check
check_updates
log_monitoring
server_hardening
audit_summaray


echo "Security audit completed. Report saved to: $REPORT_FILE"
 