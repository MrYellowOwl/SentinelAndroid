package com.yellowowl.sentinel

/**
 * Generates copy-ready commands for the operator's laptop, based on what a scan found. The phone does the
 * recon and hands off the exact next command to a full toolkit (nmap, smbclient, wpscan, testssl.sh, …).
 * Pure — it only builds strings; Sentinel never runs these. Unit tested.
 */
data class HandoffCommand(val label: String, val command: String)

object Handoff {
    /** Commands for a host, tailored to its open ports. [target] is the IP (or hostname when resolved). */
    fun forDevice(device: DeviceResult): List<HandoffCommand> {
        val target = device.ipAddress
        val out = LinkedHashMap<String, HandoffCommand>() // dedup by command, keep order

        fun add(label: String, cmd: String) { out.putIfAbsent(cmd, HandoffCommand(label, cmd)) }

        val openPorts = device.openPorts.map { it.port }
        if (openPorts.isNotEmpty()) {
            val portList = openPorts.sorted().joinToString(",")
            add("Full service + default-script scan", "nmap -sV -sC -p$portList $target")
        } else {
            add("Service scan (top ports)", "nmap -sV --top-ports 1000 $target")
        }

        for (port in openPorts) {
            when (port) {
                22 -> {
                    add("SSH connect", "ssh user@$target")
                    add("SSH algorithm audit", "nmap --script ssh2-enum-algos -p22 $target")
                }
                21 -> {
                    add("FTP connect", "ftp $target")
                    add("FTP anonymous check", "nmap --script ftp-anon -p21 $target")
                }
                23 -> add("Telnet connect", "telnet $target")
                25, 587 -> add("SMTP command audit", "nmap --script smtp-commands,smtp-open-relay -p$port $target")
                53 -> add("DNS zone-transfer attempt", "dig AXFR @$target")
                80, 8080, 8000, 8888, 5000, 8008, 8081, 9000 -> {
                    add("HTTP headers", "curl -sI http://$target:$port")
                    add("Web server scan", "nikto -h http://$target:$port")
                    add("Content discovery", "gobuster dir -u http://$target:$port -w /usr/share/wordlists/dirb/common.txt")
                }
                443, 8443 -> {
                    add("TLS configuration audit", "testssl.sh $target:$port")
                    add("Certificate inspection", "openssl s_client -connect $target:$port -servername $target </dev/null")
                }
                139, 445 -> {
                    add("SMB share listing", "smbclient -L //$target -N")
                    add("SMB enumeration", "enum4linux -a $target")
                    add("SMB vuln check", "nmap --script smb-vuln* -p445 $target")
                }
                3389 -> add("RDP connect", "xfreerdp /v:$target")
                3306 -> add("MySQL connect", "mysql -h $target -u root -p")
                5432 -> add("PostgreSQL connect", "psql -h $target -U postgres")
                5900 -> add("VNC connect", "vncviewer $target")
                6379 -> add("Redis connect", "redis-cli -h $target")
                161 -> add("SNMP walk", "snmpwalk -v2c -c public $target")
                27017 -> add("MongoDB connect", "mongosh --host $target")
                9100 -> add("Printer check", "nmap --script pjl-ready-message -p9100 $target")
            }
        }
        return out.values.toList()
    }

    /** Commands for a website host. */
    fun forWebHost(host: String, isWordPress: Boolean): List<HandoffCommand> {
        val scheme = "https"
        val out = ArrayList<HandoffCommand>()
        out += HandoffCommand("Headers", "curl -sI $scheme://$host")
        out += HandoffCommand("TLS audit", "testssl.sh $host")
        out += HandoffCommand("Web server scan", "nikto -h $scheme://$host")
        if (isWordPress) {
            out += HandoffCommand("WordPress scan", "wpscan --url $scheme://$host --enumerate vp,vt,u")
        }
        return out
    }
}
