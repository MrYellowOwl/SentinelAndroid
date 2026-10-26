package com.yellowowl.sentinel

/**
 * Pure inference of who hosts a site, who runs its DNS, and who handles its email — from the ASN/org
 * string, the Server header, name-server hostnames and MX records. Best-effort name mapping; unknown
 * inputs return null so the raw values can still be shown.
 */
object WebInfer {
    private val hostingMap = listOf(
        "cloudflare" to "Cloudflare", "amazon" to "Amazon AWS", "aws" to "Amazon AWS",
        "google" to "Google Cloud", "microsoft" to "Microsoft Azure", "azure" to "Microsoft Azure",
        "digitalocean" to "DigitalOcean", "linode" to "Akamai (Linode)", "akamai" to "Akamai",
        "fastly" to "Fastly", "ovh" to "OVH", "hetzner" to "Hetzner",
        "automattic" to "WordPress.com (Automattic)", "wpengine" to "WP Engine", "wp engine" to "WP Engine",
        "squarespace" to "Squarespace", "wix" to "Wix", "shopify" to "Shopify",
        "godaddy" to "GoDaddy", "newfold" to "Newfold (Bluehost/HostGator)", "bluehost" to "Bluehost",
        "hostgator" to "HostGator", "namecheap" to "Namecheap", "dreamhost" to "DreamHost",
        "siteground" to "SiteGround", "netlify" to "Netlify", "vercel" to "Vercel",
        "github" to "GitHub Pages", "fly.io" to "Fly.io", "rackspace" to "Rackspace",
        "unified layer" to "Bluehost (Unified Layer)", "liquid web" to "Liquid Web",
    )

    /** Hosting/CDN provider from the ASN/org string (preferred), falling back to the Server header. */
    fun hostingProvider(asOrg: String?, server: String?): String? {
        val hay = ((asOrg ?: "") + " " + (server ?: "")).lowercase()
        return hostingMap.firstOrNull { hay.contains(it.first) }?.second
    }

    private val nsMap = listOf(
        "cloudflare" to "Cloudflare", "awsdns" to "Amazon Route 53", "domaincontrol.com" to "GoDaddy",
        "googledomains" to "Google Domains", "google.com" to "Google Cloud DNS", "nsone" to "NS1",
        "dnsmadeeasy" to "DNS Made Easy", "ultradns" to "UltraDNS", "akam.net" to "Akamai",
        "registrar-servers.com" to "Namecheap", "name-services.com" to "Enom", "wixdns" to "Wix",
        "squarespace" to "Squarespace", "shopify" to "Shopify", "wordpress.com" to "WordPress.com",
        "bluehost.com" to "Bluehost", "hostgator.com" to "HostGator", "digitalocean.com" to "DigitalOcean",
        "dreamhost.com" to "DreamHost", "azure-dns" to "Microsoft Azure DNS", "cloudns" to "ClouDNS",
    )

    /** Who operates the DNS, inferred from the name-server hostnames. */
    fun dnsHost(nameServers: List<String>): String? {
        val hay = nameServers.joinToString(" ").lowercase()
        return nsMap.firstOrNull { hay.contains(it.first) }?.second
    }

    private val mxMap = listOf(
        "google.com" to "Google Workspace", "googlemail.com" to "Google Workspace",
        "outlook.com" to "Microsoft 365", "protection.outlook.com" to "Microsoft 365",
        "pphosted.com" to "Proofpoint", "mimecast.com" to "Mimecast", "zoho.com" to "Zoho Mail",
        "messagingengine.com" to "Fastmail", "secureserver.net" to "GoDaddy Email",
        "improvmx.com" to "ImprovMX", "mailgun.org" to "Mailgun", "sendgrid.net" to "SendGrid",
        "emailsrvr.com" to "Rackspace Email", "qq.com" to "Tencent", "yandex" to "Yandex",
        "hostedemail.com" to "Open-Xchange (host)", "mx.cloudflare.net" to "Cloudflare Email Routing",
    )

    /** Email provider inferred from the MX hostnames. */
    fun emailProvider(mxRecords: List<String>): String? {
        val hay = mxRecords.joinToString(" ").lowercase()
        return mxMap.firstOrNull { hay.contains(it.first) }?.second
    }
}
