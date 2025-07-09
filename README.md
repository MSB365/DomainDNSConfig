# PowerShell DNS Configuration Checker

A comprehensive PowerShell script for checking public DNS configuration of domains with a special focus on autodiscover settings. Perfect for system administrators, IT professionals, and anyone managing email infrastructure.

## 🚀 Features

- **Autodiscover Focus**: Specifically checks for Exchange/Outlook autodiscover configuration
- **Comprehensive DNS Analysis**: Queries all common DNS record types (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV)
- **Console Output**: Color-coded, organized results displayed directly in PowerShell
- **HTML Reports**: Professional-looking HTML reports with responsive design
- **Easy to Use**: Simple command-line interface with clear parameters
- **Error Handling**: Graceful handling of DNS resolution failures

## 📋 Prerequisites

- Windows PowerShell 5.1 or PowerShell Core 6.0+
- Network connectivity to query public DNS servers
- Appropriate permissions to resolve DNS records

## 🛠️ Installation

1. **Download the script**:
   ```powershell
   # Clone the repository
   git clone https://github.com/yourusername/powershell-dns-checker.git
   cd powershell-dns-checker
   ```

2. **Set execution policy** (if needed):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## 🎯 Usage

### Basic Usage

Check DNS configuration and display results in console:

```powershell
.\\Get-DomainDNSConfig.ps1 -Domain "contoso.com"
```

### Generate HTML Report

Check DNS configuration and generate an HTML report:

```powershell
.\\Get-DomainDNSConfig.ps1 -Domain "contoso.com" -GenerateHTMLReport
```

### Specify Output Path

Generate HTML report in a specific directory:

```powershell
.\\Get-DomainDNSConfig.ps1 -Domain "contoso.com" -GenerateHTMLReport -OutputPath "C:\\Reports\\"
```

## 📊 What It Checks

### Autodiscover Configuration
- **autodiscover.domain.com** A records
- **autodiscover.domain.com** CNAME records  
- **\_autodiscover.\_tcp.domain.com** SRV records

### All DNS Records
- **A Records**: IPv4 addresses
- **AAAA Records**: IPv6 addresses
- **CNAME Records**: Canonical name aliases
- **MX Records**: Mail exchange servers
- **TXT Records**: Text records (SPF, DKIM, DMARC, etc.)
- **NS Records**: Name servers
- **SOA Records**: Start of Authority
- **SRV Records**: Service records

## 📸 Sample Output

### Console Output
```
=== DNS Configuration Checker ===
Domain: contoso.com
=================================================

AUTODISCOVER CONFIGURATION
===========================
Checking: autodiscover.contoso.com
Checking: _autodiscover._tcp.contoso.com

Type Name                           Value              TTL
---- ----                           -----              ---
A    autodiscover.contoso.com       192.168.1.100      3600
CNAME autodiscover.contoso.com      mail.contoso.com   3600

✅ Autodiscover records found: 2

ALL DNS RECORDS
===============
Querying A records for contoso.com...
Querying MX records for contoso.com...
...

--- A Records ---
Name         Value          TTL
----         -----          ---
contoso.com  192.168.1.10   3600

--- MX Records ---
Name         Value                              TTL
----         -----                              ---
contoso.com  Priority: 10, Exchange: mail...   3600

✅ Total DNS records found: 15
```

### HTML Report Features
- 📱 **Responsive Design**: Works on desktop and mobile
- 🎨 **Professional Styling**: Clean, modern interface
- 📊 **Organized Data**: Records grouped by type
- 🔍 **Easy Navigation**: Clear sections and formatting
- 📅 **Timestamp**: Generation date and time included

## 🔧 Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `Domain` | String | Yes | The domain to check DNS configuration for |
| `GenerateHTMLReport` | Switch | No | Generate an HTML report |
| `OutputPath` | String | No | Path to save HTML report (default: current directory) |

## 📝 Examples

### Example 1: Basic Domain Check
```powershell
.\\Get-DomainDNSConfig-Simple.ps1 -Domain "microsoft.com"
```

### Example 2: Multiple Domains with Reports
```powershell
# Check multiple domains and generate reports
$domains = @("microsoft.com", "google.com", "github.com")
foreach ($domain in $domains) {
    .\\Get-DomainDNSConfig-Simple.ps1 -Domain $domain -GenerateHTMLReport -OutputPath "C:\\DNSReports\\"
}
```

### Example 3: Scheduled Task
```powershell
# Create a scheduled task to check domain daily
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\\Scripts\\Get-DomainDNSConfig-Simple.ps1 -Domain 'yourcompany.com' -GenerateHTMLReport -OutputPath 'C:\\Reports\\'"
$trigger = New-ScheduledTaskTrigger -Daily -At "09:00AM"
Register-ScheduledTask -TaskName "Daily DNS Check" -Action $action -Trigger $trigger
```

## 🐛 Troubleshooting

### Common Issues

**Issue**: "Execution of scripts is disabled on this system"
```powershell
# Solution: Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Issue**: "No DNS records found"
- Check internet connectivity
- Verify domain name spelling
- Ensure domain exists and is publicly accessible

**Issue**: "Access denied" when saving HTML report
- Check write permissions to output directory
- Run PowerShell as Administrator if needed

### DNS Resolution Issues
- The script uses public DNS resolution
- Some corporate networks may block external DNS queries
- Try running from a different network if issues persist

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for system administrators and IT professionals
- Inspired by the need for quick DNS configuration verification
- Special focus on Exchange/Outlook autodiscover troubleshooting

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/yourusername/powershell-dns-checker/issues) page
2. Create a new issue with detailed information
3. Include PowerShell version and error messages

## 🔄 Version History

- **v1.0.0** - Initial release
  - Basic DNS record checking
  - Autodiscover configuration detection
  - HTML report generation
  - Console output formatting


## 🚀 Quick Start

```powershell
# Download and run in one command
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/powershell-dns-checker/main/Get-DomainDNSConfig-Simple.ps1" -OutFile "Get-DomainDNSConfig-Simple.ps1"
.\\Get-DomainDNSConfig-Simple.ps1 -Domain "yourdomain.com" -GenerateHTMLReport
```
```



