#region Description
<#     
.NOTES
==============================================================================
Created on:         2025/07/09
Created by:         Drago Petrovic
Organization:       MSB365.blog
Filename:           Get-DomainDNSConfig-Complete.ps1
Current version:    V1.0     

Find us on:
* Website:         https://www.msb365.blog
* Technet:         https://social.technet.microsoft.com/Profile/MSB365
* LinkedIn:        https://www.linkedin.com/in/drago-petrovic/
* MVP Profile:     https://mvp.microsoft.com/de-de/PublicProfile/5003446
==============================================================================

.SYNOPSIS
    Complete DNS Configuration Checker with all features combined
.DESCRIPTION
    Comprehensive DNS analysis tool combining basic DNS checking, autodiscover focus, 
    custom DNS servers, batch processing, propagation checking, email security validation, 
    and multiple export formats with user-selectable options.
.PARAMETER Domain
    Single domain to check DNS configuration for
.PARAMETER BatchFile
    CSV file containing domains to process in batch (must have 'Domain' column)
.PARAMETER CustomDNSServers
    Array of custom DNS servers to query (e.g., @("8.8.8.8", "1.1.1.1"))
.PARAMETER CheckAutodiscover
    Check autodiscover configuration (default: true)
.PARAMETER CheckAllRecords
    Check all standard DNS record types (default: true)
.PARAMETER CheckPropagation
    Check DNS propagation across multiple public DNS servers
.PARAMETER ValidateEmail
    Perform email-specific validation (SPF, DKIM, DMARC)
.PARAMETER GenerateHTMLReport
    Generate comprehensive HTML report
.PARAMETER ExportJSON
    Export results to JSON format
.PARAMETER ExportCSV
    Export results to CSV format
.PARAMETER OutputPath
    Path where to save reports (default: current directory)
.PARAMETER Verbose
    Enable verbose output with detailed progress information
.EXAMPLE
    .\Get-DomainDNSConfig-Complete.ps1 -Domain "contoso.com"
.EXAMPLE
    .\Get-DomainDNSConfig-Complete.ps1 -Domain "contoso.com" -CheckPropagation -ValidateEmail -GenerateHTMLReport -ExportJSON
.EXAMPLE
    .\Get-DomainDNSConfig-Complete.ps1 -BatchFile "domains.csv" -CheckAllRecords -ValidateEmail -ExportCSV -GenerateHTMLReport

.COPYRIGHT
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
===========================================================================
.CHANGE LOG
V1.00, 2025/07/09 - DrPe - Initial version



--- keep it simple, but significant ---


--- by MSB365 Blog ---

#>



param(
    [string]$Domain,
    [string]$BatchFile,
    [string[]]$CustomDNSServers = @(),
    [switch]$CheckAutodiscover = $true,
    [switch]$CheckAllRecords = $true,
    [switch]$CheckPropagation,
    [switch]$ValidateEmail,
    [switch]$GenerateHTMLReport,
    [switch]$ExportJSON,
    [switch]$ExportCSV,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$VerboseOutput
)

# Public DNS servers for propagation checking
$PublicDNSServers = @{
    "Google-Primary" = "8.8.8.8"
    "Google-Secondary" = "8.8.4.4"
    "Cloudflare-Primary" = "1.1.1.1"
    "Cloudflare-Secondary" = "1.0.0.1"
    "Quad9" = "9.9.9.9"
    "OpenDNS" = "208.67.222.222"
    "Comodo" = "8.26.56.26"
    "CleanBrowsing" = "185.228.168.9"
}

# Global results collection
$Global:AllDomainResults = @()

function Write-ColorOutput {
    param(
        [string]$Message,
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    try {
        if ($NoNewline) {
            Write-Host $Message -ForegroundColor $Color -NoNewline
        } else {
            Write-Host $Message -ForegroundColor $Color
        }
    }
    catch {
        # Fallback to basic Write-Host if color fails
        Write-Host $Message
    }
}

function Write-VerboseOutput {
    param([string]$Message)
    
    if ($VerboseOutput) {
        Write-ColorOutput "[VERBOSE] $Message" "Gray"
    }
}

function Get-DNSRecords {
    param(
        [string]$Domain,
        [string]$RecordType,
        [string]$DNSServer = $null
    )
    
    try {
        if ($DNSServer) {
            Write-VerboseOutput "Querying $RecordType record for $Domain via $DNSServer"
            $records = Resolve-DnsName -Name $Domain -Type $RecordType -Server $DNSServer -ErrorAction SilentlyContinue
        } else {
            Write-VerboseOutput "Querying $RecordType record for $Domain"
            $records = Resolve-DnsName -Name $Domain -Type $RecordType -ErrorAction SilentlyContinue
        }
        return $records
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-VerboseOutput "Error querying $RecordType for $Domain : $errorMsg"
        return $null
    }
}

function Get-AutodiscoverConfig {
    param(
        [string]$Domain,
        [string]$DNSServer = $null
    )
    
    if (-not $CheckAutodiscover) {
        Write-VerboseOutput "Autodiscover check skipped by user choice"
        return @()
    }
    
    $autodiscoverResults = @()
    
    $autodiscoverDomains = @(
        "autodiscover.$Domain",
        "_autodiscover._tcp.$Domain"
    )
    
    Write-ColorOutput "🔍 Checking Autodiscover Configuration..." "Magenta"
    
    foreach ($autoDomain in $autodiscoverDomains) {
        Write-ColorOutput "  Checking: $autoDomain" "Yellow"
        
        # Check A record
        $aRecord = Get-DNSRecords -Domain $autoDomain -RecordType "A" -DNSServer $DNSServer
        if ($aRecord) {
            $aRecords = $aRecord | Where-Object {$_.Type -eq "A"}
            foreach ($record in $aRecords) {
                $autodiscoverResults += [PSCustomObject]@{
                    Category = "Autodiscover"
                    Type = "A"
                    Name = $autoDomain
                    Value = $record.IPAddress
                    TTL = $record.TTL
                    DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                    Status = "Found"
                    Timestamp = Get-Date
                }
            }
        }
        
        # Check CNAME record
        $cnameRecord = Get-DNSRecords -Domain $autoDomain -RecordType "CNAME" -DNSServer $DNSServer
        if ($cnameRecord) {
            $cnameRecords = $cnameRecord | Where-Object {$_.Type -eq "CNAME"}
            foreach ($record in $cnameRecords) {
                $autodiscoverResults += [PSCustomObject]@{
                    Category = "Autodiscover"
                    Type = "CNAME"
                    Name = $autoDomain
                    Value = $record.NameHost
                    TTL = $record.TTL
                    DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                    Status = "Found"
                    Timestamp = Get-Date
                }
            }
        }
        
        # Check SRV record for _autodiscover._tcp
        if ($autoDomain -like "*_tcp*") {
            $srvRecord = Get-DNSRecords -Domain $autoDomain -RecordType "SRV" -DNSServer $DNSServer
            if ($srvRecord) {
                $srvRecords = $srvRecord | Where-Object {$_.Type -eq "SRV"}
                foreach ($record in $srvRecords) {
                    $srvValue = "Priority: $($record.Priority), Weight: $($record.Weight), Port: $($record.Port), Target: $($record.NameTarget)"
                    $autodiscoverResults += [PSCustomObject]@{
                        Category = "Autodiscover"
                        Type = "SRV"
                        Name = $autoDomain
                        Value = $srvValue
                        TTL = $record.TTL
                        DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                        Status = "Found"
                        Timestamp = Get-Date
                    }
                }
            }
        }
    }
    
    if ($autodiscoverResults.Count -eq 0) {
        Write-ColorOutput "  ❌ No autodiscover records found" "Red"
    } else {
        Write-ColorOutput "  ✅ Found $($autodiscoverResults.Count) autodiscover record(s)" "Green"
    }
    
    return $autodiscoverResults
}

function Get-AllDNSRecords {
    param(
        [string]$Domain,
        [string]$DNSServer = $null
    )
    
    if (-not $CheckAllRecords) {
        Write-VerboseOutput "All DNS records check skipped by user choice"
        return @()
    }
    
    $allRecords = @()
    $recordTypes = @("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV")
    
    Write-ColorOutput "📋 Checking All DNS Records..." "Magenta"
    
    foreach ($recordType in $recordTypes) {
        Write-ColorOutput "  Querying $recordType records..." "Cyan"
        
        $records = Get-DNSRecords -Domain $Domain -RecordType $recordType -DNSServer $DNSServer
        
        if ($records) {
            foreach ($record in $records) {
                $value = ""
                switch ($record.Type) {
                    "A" { 
                        $value = $record.IPAddress 
                    }
                    "AAAA" { 
                        $value = $record.IPAddress 
                    }
                    "CNAME" { 
                        $value = $record.NameHost 
                    }
                    "MX" { 
                        $value = "Priority: $($record.Preference), Exchange: $($record.NameExchange)" 
                    }
                    "TXT" { 
                        $value = $record.Strings -join " " 
                    }
                    "NS" { 
                        $value = $record.NameHost 
                    }
                    "SOA" { 
                        $value = "Primary: $($record.PrimaryServer), Admin: $($record.NameAdministrator), Serial: $($record.SerialNumber)" 
                    }
                    "SRV" { 
                        $value = "Priority: $($record.Priority), Weight: $($record.Weight), Port: $($record.Port), Target: $($record.NameTarget)" 
                    }
                    default { 
                        $value = $record.ToString() 
                    }
                }
                
                $allRecords += [PSCustomObject]@{
                    Category = "DNS"
                    Type = $record.Type
                    Name = $record.Name
                    Value = $value
                    TTL = $record.TTL
                    DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                    Status = "Found"
                    Timestamp = Get-Date
                }
            }
        }
    }
    
    Write-ColorOutput "  ✅ Found $($allRecords.Count) DNS record(s)" "Green"
    return $allRecords
}

function Test-EmailSecurity {
    param(
        [string]$Domain,
        [string]$DNSServer = $null
    )
    
    if (-not $ValidateEmail) {
        Write-VerboseOutput "Email security validation skipped by user choice"
        return @{
            Records = @()
            ValidationResults = @()
        }
    }
    
    $emailSecurityRecords = @()
    $validationResults = @()
    
    Write-ColorOutput "📧 Checking Email Security Records..." "Magenta"
    
    # Check SPF record
    Write-ColorOutput "  Checking SPF records..." "Cyan"
    $spfRecord = Get-DNSRecords -Domain $Domain -RecordType "TXT" -DNSServer $DNSServer
    if ($spfRecord) {
        $spfRecords = $spfRecord | Where-Object {$_.Strings -like "*v=spf1*"}
        foreach ($record in $spfRecords) {
            $spfValue = $record.Strings -join " "
            $emailSecurityRecords += [PSCustomObject]@{
                Category = "Email-Security"
                Type = "SPF"
                Name = $Domain
                Value = $spfValue
                TTL = $record.TTL
                DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                Status = "Found"
                Timestamp = Get-Date
            }
            
            # Validate SPF record
            $spfValidation = Test-SPFRecord -SPFRecord $spfValue -Domain $Domain
            $validationResults += $spfValidation
        }
    }
    
    # Check DMARC record
    Write-ColorOutput "  Checking DMARC records..." "Cyan"
    $dmarcDomain = "_dmarc.$Domain"
    $dmarcRecord = Get-DNSRecords -Domain $dmarcDomain -RecordType "TXT" -DNSServer $DNSServer
    if ($dmarcRecord) {
        $dmarcRecords = $dmarcRecord | Where-Object {$_.Strings -like "*v=DMARC1*"}
        foreach ($record in $dmarcRecords) {
            $dmarcValue = $record.Strings -join " "
            $emailSecurityRecords += [PSCustomObject]@{
                Category = "Email-Security"
                Type = "DMARC"
                Name = $dmarcDomain
                Value = $dmarcValue
                TTL = $record.TTL
                DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                Status = "Found"
                Timestamp = Get-Date
            }
            
            # Validate DMARC record
            $dmarcValidation = Test-DMARCRecord -DMARCRecord $dmarcValue -Domain $Domain
            $validationResults += $dmarcValidation
        }
    }
    
    # Check common DKIM selectors
    Write-ColorOutput "  Checking DKIM records..." "Cyan"
    $dkimSelectors = @("default", "selector1", "selector2", "google", "k1", "dkim")
    foreach ($selector in $dkimSelectors) {
        $dkimDomain = "$selector._domainkey.$Domain"
        $dkimRecord = Get-DNSRecords -Domain $dkimDomain -RecordType "TXT" -DNSServer $DNSServer
        if ($dkimRecord) {
            $dkimRecords = $dkimRecord | Where-Object {$_.Strings -like "*v=DKIM1*" -or $_.Strings -like "*k=rsa*"}
            foreach ($record in $dkimRecords) {
                $dkimValue = $record.Strings -join " "
                $emailSecurityRecords += [PSCustomObject]@{
                    Category = "Email-Security"
                    Type = "DKIM"
                    Name = $dkimDomain
                    Value = $dkimValue
                    TTL = $record.TTL
                    DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
                    Status = "Found"
                    Timestamp = Get-Date
                }
            }
        }
    }
    
    $emailCount = $emailSecurityRecords.Count
    $validationCount = $validationResults.Count
    Write-ColorOutput "  ✅ Found $emailCount email security record(s), $validationCount validation(s)" "Green"
    
    return @{
        Records = $emailSecurityRecords
        ValidationResults = $validationResults
    }
}

function Test-SPFRecord {
    param(
        [string]$SPFRecord,
        [string]$Domain
    )
    
    $validation = [PSCustomObject]@{
        Category = "Email-Validation"
        Type = "SPF-Validation"
        Domain = $Domain
        Status = "Unknown"
        Issues = @()
        Recommendations = @()
        Timestamp = Get-Date
    }
    
    if ($SPFRecord -match "v=spf1") {
        $validation.Status = "Valid"
        
        # Check for common issues
        if ($SPFRecord -match "~all" -or $SPFRecord -match "-all") {
            $validation.Recommendations += "SPF policy is properly configured with fail/softfail"
        } elseif ($SPFRecord -match "\+all") {
            $validation.Issues += "SPF record uses +all which allows any server to send email"
            $validation.Status = "Warning"
        }
        
        # Check for too many DNS lookups
        $lookupCount = ([regex]::Matches($SPFRecord, "include:|a:|mx:|exists:")).Count
        if ($lookupCount -gt 10) {
            $validation.Issues += "SPF record may exceed 10 DNS lookup limit ($lookupCount lookups found)"
            $validation.Status = "Warning"
        }
    } else {
        $validation.Status = "Invalid"
        $validation.Issues += "SPF record does not start with v=spf1"
    }
    
    return $validation
}

function Test-DMARCRecord {
    param(
        [string]$DMARCRecord,
        [string]$Domain
    )
    
    $validation = [PSCustomObject]@{
        Category = "Email-Validation"
        Type = "DMARC-Validation"
        Domain = $Domain
        Status = "Unknown"
        Issues = @()
        Recommendations = @()
        Timestamp = Get-Date
    }
    
    if ($DMARCRecord -match "v=DMARC1") {
        $validation.Status = "Valid"
        
        # Check policy
        if ($DMARCRecord -match "p=none") {
            $validation.Recommendations += "DMARC policy is set to 'none' - consider upgrading to 'quarantine' or 'reject'"
        } elseif ($DMARCRecord -match "p=quarantine") {
            $validation.Recommendations += "DMARC policy is set to 'quarantine' - good security level"
        } elseif ($DMARCRecord -match "p=reject") {
            $validation.Recommendations += "DMARC policy is set to 'reject' - highest security level"
        }
        
        # Check for reporting
        if ($DMARCRecord -notmatch "rua=") {
            $validation.Issues += "No aggregate reporting address (rua) specified"
        }
    } else {
        $validation.Status = "Invalid"
        $validation.Issues += "DMARC record does not start with v=DMARC1"
    }
    
    return $validation
}

function Test-DNSPropagation {
    param(
        [string]$Domain,
        [hashtable]$DNSServers = $PublicDNSServers
    )
    
    if (-not $CheckPropagation) {
        Write-VerboseOutput "DNS propagation check skipped by user choice"
        return @()
    }
    
    $propagationResults = @()
    
    Write-ColorOutput "🌐 Checking DNS Propagation..." "Magenta"
    
    foreach ($serverName in $DNSServers.Keys) {
        $serverIP = $DNSServers[$serverName]
        Write-ColorOutput "  Checking $serverName ($serverIP)..." "Yellow"
        
        try {
            # Check A record propagation
            $aRecord = Get-DNSRecords -Domain $Domain -RecordType "A" -DNSServer $serverIP
            if ($aRecord) {
                $aRecords = $aRecord | Where-Object {$_.Type -eq "A"}
                foreach ($record in $aRecords) {
                    $propagationResults += [PSCustomObject]@{
                        Category = "Propagation"
                        Type = "A"
                        Name = $Domain
                        Value = $record.IPAddress
                        TTL = $record.TTL
                        DNSServer = $serverName
                        ServerIP = $serverIP
                        Status = "Resolved"
                        Timestamp = Get-Date
                    }
                }
            } else {
                $propagationResults += [PSCustomObject]@{
                    Category = "Propagation"
                    Type = "A"
                    Name = $Domain
                    Value = "No record found"
                    TTL = "N/A"
                    DNSServer = $serverName
                    ServerIP = $serverIP
                    Status = "Not Resolved"
                    Timestamp = Get-Date
                }
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            $propagationResults += [PSCustomObject]@{
                Category = "Propagation"
                Type = "A"
                Name = $Domain
                Value = "Query failed: $errorMessage"
                TTL = "N/A"
                DNSServer = $serverName
                ServerIP = $serverIP
                Status = "Error"
                Timestamp = Get-Date
            }
        }
    }
    
    $resolvedCount = ($propagationResults | Where-Object {$_.Status -eq "Resolved"}).Count
    $totalCount = $propagationResults.Count
    Write-ColorOutput "  ✅ Propagation check complete: $resolvedCount/$totalCount servers resolved" "Green"
    
    return $propagationResults
}

function Import-DomainsFromCSV {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) {
            throw "CSV file not found: $FilePath"
        }
        
        $domains = Import-Csv $FilePath
        
        # Validate CSV structure
        if (-not ($domains | Get-Member -Name "Domain" -MemberType NoteProperty)) {
            throw "CSV file must contain a 'Domain' column"
        }
        
        Write-ColorOutput "✅ Imported $($domains.Count) domain(s) from CSV" "Green"
        return $domains
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ColorOutput "❌ Error importing CSV file: $errorMessage" "Red"
        return $null
    }
}

function Export-ResultsToJSON {
    param(
        [object]$Results,
        [string]$OutputPath,
        [string]$Domain
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $filename = "DNS-Results-$($Domain.Replace('.', '-'))-$timestamp.json"
    $fullPath = Join-Path $OutputPath $filename
    
    try {
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $fullPath -Encoding UTF8
        Write-ColorOutput "✅ JSON exported: $fullPath" "Green"
        return $fullPath
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ColorOutput "❌ Error exporting JSON: $errorMessage" "Red"
        return $null
    }
}

function Export-ResultsToCSV {
    param(
        [array]$AllRecords,
        [string]$OutputPath,
        [string]$Domain
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $filename = "DNS-Results-$($Domain.Replace('.', '-'))-$timestamp.csv"
    $fullPath = Join-Path $OutputPath $filename
    
    try {
        $AllRecords | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "✅ CSV exported: $fullPath" "Green"
        return $fullPath
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ColorOutput "❌ Error exporting CSV: $errorMessage" "Red"
        return $null
    }
}

function Create-ComprehensiveHTMLReport {
    param(
        [string]$Domain,
        [array]$AllRecords,
        [array]$ValidationResults,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $filename = "DNS-Complete-Report-$($Domain.Replace('.', '-'))-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $fullPath = Join-Path $OutputPath $filename
    
    # Categorize records
    $autodiscoverRecords = $AllRecords | Where-Object {$_.Category -eq "Autodiscover"}
    $dnsRecords = $AllRecords | Where-Object {$_.Category -eq "DNS"}
    $emailRecords = $AllRecords | Where-Object {$_.Category -eq "Email-Security"}
    $propagationRecords = $AllRecords | Where-Object {$_.Category -eq "Propagation"}
    
    # Create HTML content
    $html = @()
    $html += '<!DOCTYPE html>'
    $html += '<html lang="en">'
    $html += '<head>'
    $html += '<meta charset="UTF-8">'
    $html += '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
    $html += "<title>Complete DNS Analysis Report - $Domain</title>"
    $html += '<style>'
    $html += 'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }'
    $html += '.container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }'
    $html += '.header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 30px; text-align: center; }'
    $html += '.header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }'
    $html += '.header .subtitle { margin: 10px 0 0 0; opacity: 0.9; font-size: 1.1em; }'
    $html += '.content { padding: 30px; }'
    $html += '.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }'
    $html += '.summary-card { background: #f8f9fa; border-radius: 8px; padding: 20px; border-left: 4px solid #3498db; }'
    $html += '.summary-card h3 { margin: 0 0 10px 0; color: #2c3e50; font-size: 1.1em; }'
    $html += '.summary-card .number { font-size: 2em; font-weight: bold; color: #3498db; }'
    $html += '.section { margin-bottom: 40px; }'
    $html += '.section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; display: flex; align-items: center; }'
    $html += '.section h2 .emoji { margin-right: 10px; font-size: 1.2em; }'
    $html += 'table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }'
    $html += 'th { background: #3498db; color: white; padding: 15px; text-align: left; font-weight: 600; }'
    $html += 'td { padding: 12px 15px; border-bottom: 1px solid #eee; }'
    $html += 'tr:hover { background: #f8f9fa; }'
    $html += '.status-found { color: #27ae60; font-weight: bold; }'
    $html += '.status-resolved { background: #d5f4e6; }'
    $html += '.status-not-resolved { background: #fadbd8; }'
    $html += '.status-error { background: #f8d7da; }'
    $html += '.status-valid { color: #27ae60; font-weight: bold; }'
    $html += '.status-warning { color: #f39c12; font-weight: bold; }'
    $html += '.status-invalid { color: #e74c3c; font-weight: bold; }'
    $html += '.value-cell { max-width: 400px; word-wrap: break-word; font-family: monospace; font-size: 0.9em; }'
    $html += '.no-records { text-align: center; padding: 40px; color: #7f8c8d; font-style: italic; }'
    $html += '.validation-item { background: #f8f9fa; border-radius: 6px; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }'
    $html += '.validation-issues { color: #e74c3c; margin: 5px 0; }'
    $html += '.validation-recommendations { color: #27ae60; margin: 5px 0; }'
    $html += '.footer { background: #2c3e50; color: white; padding: 20px; text-align: center; }'
    $html += '@media (max-width: 768px) { .summary-grid { grid-template-columns: 1fr; } table { font-size: 0.9em; } }'
    $html += '</style>'
    $html += '</head>'
    $html += '<body>'
    $html += '<div class="container">'
    
    # Header
    $html += '<div class="header">'
    $html += '<h1>Complete DNS Analysis Report</h1>'
    $html += "<div class='subtitle'>Domain: $Domain | Generated: $timestamp</div>"
    $html += '</div>'
    
    # Content
    $html += '<div class="content">'
    
    # Summary cards
    $html += '<div class="summary-grid">'
    $html += '<div class="summary-card">'
    $html += '<h3>Total Records</h3>'
    $html += "<div class='number'>$($AllRecords.Count)</div>"
    $html += '</div>'
    $html += '<div class="summary-card">'
    $html += '<h3>Autodiscover Records</h3>'
    $html += "<div class='number'>$($autodiscoverRecords.Count)</div>"
    $html += '</div>'
    $html += '<div class="summary-card">'
    $html += '<h3>Email Security Records</h3>'
    $html += "<div class='number'>$($emailRecords.Count)</div>"
    $html += '</div>'
    $html += '<div class="summary-card">'
    $html += '<h3>DNS Servers Checked</h3>'
    $uniqueServers = $propagationRecords | Select-Object DNSServer -Unique
    $html += "<div class='number'>$($uniqueServers.Count)</div>"
    $html += '</div>'
    $html += '</div>'
    
    # Autodiscover section
    if ($autodiscoverRecords.Count -gt 0) {
        $html += '<div class="section">'
        $html += '<h2><span class="emoji">🔍</span>Autodiscover Configuration</h2>'
        $html += '<table>'
        $html += '<thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th><th>DNS Server</th><th>Status</th></tr></thead>'
        $html += '<tbody>'
        
        foreach ($record in $autodiscoverRecords) {
            $html += '<tr>'
            $html += "<td><strong>$($record.Type)</strong></td>"
            $html += "<td>$($record.Name)</td>"
            $html += "<td class='value-cell'>$($record.Value)</td>"
            $html += "<td>$($record.TTL)</td>"
            $html += "<td>$($record.DNSServer)</td>"
            $html += "<td class='status-found'>$($record.Status)</td>"
            $html += '</tr>'
        }
        
        $html += '</tbody></table>'
        $html += '</div>'
    }
    
    # Email Security section
    if ($emailRecords.Count -gt 0 -or $ValidationResults.Count -gt 0) {
        $html += '<div class="section">'
        $html += '<h2><span class="emoji">📧</span>Email Security Analysis</h2>'
        
        if ($emailRecords.Count -gt 0) {
            # Group by type
            $spfRecords = $emailRecords | Where-Object {$_.Type -eq "SPF"}
            $dkimRecords = $emailRecords | Where-Object {$_.Type -eq "DKIM"}
            $dmarcRecords = $emailRecords | Where-Object {$_.Type -eq "DMARC"}
            
            if ($spfRecords.Count -gt 0) {
                $html += '<h3>SPF Records</h3>'
                $html += '<table>'
                $html += '<thead><tr><th>Name</th><th>Value</th><th>TTL</th><th>DNS Server</th></tr></thead>'
                $html += '<tbody>'
                foreach ($record in $spfRecords) {
                    $html += '<tr>'
                    $html += "<td>$($record.Name)</td>"
                    $html += "<td class='value-cell'>$($record.Value)</td>"
                    $html += "<td>$($record.TTL)</td>"
                    $html += "<td>$($record.DNSServer)</td>"
                    $html += '</tr>'
                }
                $html += '</tbody></table>'
            }
            
            if ($dmarcRecords.Count -gt 0) {
                $html += '<h3>DMARC Records</h3>'
                $html += '<table>'
                $html += '<thead><tr><th>Name</th><th>Value</th><th>TTL</th><th>DNS Server</th></tr></thead>'
                $html += '<tbody>'
                foreach ($record in $dmarcRecords) {
                    $html += '<tr>'
                    $html += "<td>$($record.Name)</td>"
                    $html += "<td class='value-cell'>$($record.Value)</td>"
                    $html += "<td>$($record.TTL)</td>"
                    $html += "<td>$($record.DNSServer)</td>"
                    $html += '</tr>'
                }
                $html += '</tbody></table>'
            }
            
            if ($dkimRecords.Count -gt 0) {
                $html += '<h3>DKIM Records</h3>'
                $html += '<table>'
                $html += '<thead><tr><th>Name</th><th>Value</th><th>TTL</th><th>DNS Server</th></tr></thead>'
                $html += '<tbody>'
                foreach ($record in $dkimRecords) {
                    $html += '<tr>'
                    $html += "<td>$($record.Name)</td>"
                    $html += "<td class='value-cell'>$($record.Value)</td>"
                    $html += "<td>$($record.TTL)</td>"
                    $html += "<td>$($record.DNSServer)</td>"
                    $html += '</tr>'
                }
                $html += '</tbody></table>'
            }
        }
        
        # Validation results
        if ($ValidationResults.Count -gt 0) {
            $html += '<h3>Security Validation Results</h3>'
            foreach ($validation in $ValidationResults) {
                $statusClass = switch ($validation.Status) {
                    "Valid" { "status-valid" }
                    "Warning" { "status-warning" }
                    "Invalid" { "status-invalid" }
                    default { "" }
                }
                
                $html += '<div class="validation-item">'
                $html += "<h4>$($validation.Type) - <span class='$statusClass'>$($validation.Status)</span></h4>"
                
                if ($validation.Issues.Count -gt 0) {
                    $html += '<div class="validation-issues"><strong>Issues:</strong><ul>'
                    foreach ($issue in $validation.Issues) {
                        $html += "<li>$issue</li>"
                    }
                    $html += '</ul></div>'
                }
                
                if ($validation.Recommendations.Count -gt 0) {
                    $html += '<div class="validation-recommendations"><strong>Recommendations:</strong><ul>'
                    foreach ($rec in $validation.Recommendations) {
                        $html += "<li>$rec</li>"
                    }
                    $html += '</ul></div>'
                }
                
                $html += '</div>'
            }
        }
        
        $html += '</div>'
    }
    
    # DNS Propagation section
    if ($propagationRecords.Count -gt 0) {
        $html += '<div class="section">'
        $html += '<h2><span class="emoji">🌐</span>DNS Propagation Check</h2>'
        $html += '<table>'
        $html += '<thead><tr><th>DNS Server</th><th>Server IP</th><th>Type</th><th>Value</th><th>TTL</th><th>Status</th></tr></thead>'
        $html += '<tbody>'
        
        foreach ($result in $propagationRecords) {
            $statusClass = switch ($result.Status) {
                "Resolved" { "status-resolved" }
                "Not Resolved" { "status-not-resolved" }
                "Error" { "status-error" }
                default { "" }
            }
            
            $html += "<tr class='$statusClass'>"
            $html += "<td>$($result.DNSServer)</td>"
            $html += "<td>$($result.ServerIP)</td>"
            $html += "<td>$($result.Type)</td>"
            $html += "<td class='value-cell'>$($result.Value)</td>"
            $html += "<td>$($result.TTL)</td>"
            $html += "<td>$($result.Status)</td>"
            $html += '</tr>'
        }
        
        $html += '</tbody></table>'
        $html += '</div>'
    }
    
    # All DNS Records section
    if ($dnsRecords.Count -gt 0) {
        $html += '<div class="section">'
        $html += '<h2><span class="emoji">📋</span>All DNS Records</h2>'
        
        $groupedRecords = $dnsRecords | Group-Object Type | Sort-Object Name
        
        foreach ($group in $groupedRecords) {
            $html += "<h3>$($group.Name) Records</h3>"
            $html += '<table>'
            $html += '<thead><tr><th>Name</th><th>Value</th><th>TTL</th><th>DNS Server</th></tr></thead>'
            $html += '<tbody>'
            
            foreach ($record in $group.Group) {
                $html += '<tr>'
                $html += "<td>$($record.Name)</td>"
                $html += "<td class='value-cell'>$($record.Value)</td>"
                $html += "<td>$($record.TTL)</td>"
                $html += "<td>$($record.DNSServer)</td>"
                $html += '</tr>'
            }
            
            $html += '</tbody></table>'
        }
        
        $html += '</div>'
    }
    
    $html += '</div>'
    
    # Footer
    $html += '<div class="footer">'
    $html += 'Generated by PowerShell DNS Configuration Checker | All times in local timezone'
    $html += '</div>'
    
    $html += '</div>'
    $html += '</body>'
    $html += '</html>'

    # Write HTML to file
    $html -join "`n" | Out-File -FilePath $fullPath -Encoding UTF8
    Write-ColorOutput "✅ HTML report generated: $fullPath" "Green"
    return $fullPath
}

function Process-SingleDomain {
    param(
        [string]$Domain,
        [string[]]$DNSServers = @()
    )
    
    $allRecords = @()
    $allValidations = @()
    
    $separator = "=" * 60
    Write-ColorOutput "" "White"
    Write-ColorOutput $separator "Green"
    Write-ColorOutput "🔍 PROCESSING DOMAIN: $Domain" "Green"
    Write-ColorOutput $separator "Green"
    
    # Use custom DNS servers if provided, otherwise use default
    $serversToUse = if ($DNSServers.Count -gt 0) { $DNSServers } else { @($null) }
    
    foreach ($dnsServer in $serversToUse) {
        $serverLabel = if ($dnsServer) { $dnsServer } else { "Default" }
        Write-ColorOutput "" "White"
        Write-ColorOutput "🖥️  Using DNS Server: $serverLabel" "Cyan"
        
        # Get autodiscover configuration
        $autodiscover = Get-AutodiscoverConfig -Domain $Domain -DNSServer $dnsServer
        $allRecords += $autodiscover
        
        # Get all DNS records
        $dnsRecords = Get-AllDNSRecords -Domain $Domain -DNSServer $dnsServer
        $allRecords += $dnsRecords
        
        # Email security validation
        $emailSecurity = Test-EmailSecurity -Domain $Domain -DNSServer $dnsServer
        $allRecords += $emailSecurity.Records
        $allValidations += $emailSecurity.ValidationResults
    }
    
    # DNS propagation check (only once, not per DNS server)
    $propagation = Test-DNSPropagation -Domain $Domain
    $allRecords += $propagation
    
    # Create domain result object
    $domainResult = [PSCustomObject]@{
        Domain = $Domain
        Timestamp = Get-Date
        TotalRecords = $allRecords.Count
        AutodiscoverRecords = ($allRecords | Where-Object {$_.Category -eq "Autodiscover"}).Count
        DNSRecords = ($allRecords | Where-Object {$_.Category -eq "DNS"}).Count
        EmailSecurityRecords = ($allRecords | Where-Object {$_.Category -eq "Email-Security"}).Count
        PropagationRecords = ($allRecords | Where-Object {$_.Category -eq "Propagation"}).Count
        ValidationResults = $allValidations.Count
        AllRecords = $allRecords
        Validations = $allValidations
    }
    
    # Display summary
    Write-ColorOutput "" "White"
    Write-ColorOutput "📊 DOMAIN SUMMARY" "Magenta"
    Write-ColorOutput "=================" "Magenta"
    Write-ColorOutput "Total Records Found: $($domainResult.TotalRecords)" "White"
    Write-ColorOutput "- Autodiscover: $($domainResult.AutodiscoverRecords)" "Yellow"
    Write-ColorOutput "- DNS Records: $($domainResult.DNSRecords)" "Yellow"
    Write-ColorOutput "- Email Security: $($domainResult.EmailSecurityRecords)" "Yellow"
    Write-ColorOutput "- Propagation: $($domainResult.PropagationRecords)" "Yellow"
    Write-ColorOutput "- Validations: $($domainResult.ValidationResults)" "Yellow"
    
    return $domainResult
}

# Main script execution
Clear-Host

$banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                    COMPLETE DNS CONFIGURATION CHECKER                       ║
║                           Enhanced Version 2.0                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@

Write-ColorOutput $banner "Green"

# Display selected options
Write-ColorOutput "" "White"
Write-ColorOutput "🔧 CONFIGURATION" "Magenta"
Write-ColorOutput "================" "Magenta"
Write-ColorOutput "Autodiscover Check: $(if ($CheckAutodiscover) { '✅ Enabled' } else { '❌ Disabled' })" "White"
Write-ColorOutput "All DNS Records: $(if ($CheckAllRecords) { '✅ Enabled' } else { '❌ Disabled' })" "White"
Write-ColorOutput "Propagation Check: $(if ($CheckPropagation) { '✅ Enabled' } else { '❌ Disabled' })" "White"
Write-ColorOutput "Email Validation: $(if ($ValidateEmail) { '✅ Enabled' } else { '❌ Disabled' })" "White"
Write-ColorOutput "HTML Report: $(if ($GenerateHTMLReport) { '✅ Enabled' } else { '❌ Disabled' })" "White"
Write-ColorOutput "JSON Export: $(if ($ExportJSON) { '✅ Enabled' } else { '❌ Disabled' })" "White"
Write-ColorOutput "CSV Export: $(if ($ExportCSV) { '✅ Enabled' } else { '❌ Disabled' })" "White"
if ($CustomDNSServers.Count -gt 0) {
    Write-ColorOutput "Custom DNS Servers: $($CustomDNSServers -join ', ')" "White"
}

# Determine processing mode
if ($BatchFile) {
    # Batch processing mode
    Write-ColorOutput "" "White"
    Write-ColorOutput "📁 BATCH PROCESSING MODE" "Magenta"
    $domains = Import-DomainsFromCSV -FilePath $BatchFile
    
    if ($domains) {
        foreach ($domainEntry in $domains) {
            $domainName = $domainEntry.Domain
            $result = Process-SingleDomain -Domain $domainName -DNSServers $CustomDNSServers
            $Global:AllDomainResults += $result
        }
    } else {
        Write-ColorOutput "❌ Failed to process batch file. Exiting." "Red"
        exit 1
    }
} elseif ($Domain) {
    # Single domain mode
    Write-ColorOutput "" "White"
    Write-ColorOutput "🎯 SINGLE DOMAIN MODE" "Magenta"
    $result = Process-SingleDomain -Domain $Domain -DNSServers $CustomDNSServers
    $Global:AllDomainResults += $result
} else {
    Write-ColorOutput "" "White"
    Write-ColorOutput "❌ ERROR: Either -Domain or -BatchFile parameter is required" "Red"
    Write-ColorOutput "Use Get-Help .\Get-DomainDNSConfig-Complete-Final-Fixed.ps1 for usage examples" "Yellow"
    exit 1
}

# Export and report generation
Write-ColorOutput "" "White"
Write-ColorOutput "📤 EXPORT & REPORTING" "Magenta"
Write-ColorOutput "=====================" "Magenta"

foreach ($result in $Global:AllDomainResults) {
    $domain = $result.Domain
    
    # Export to JSON
    if ($ExportJSON) {
        $jsonPath = Export-ResultsToJSON -Results $result -OutputPath $OutputPath -Domain $domain
    }
    
    # Export to CSV
    if ($ExportCSV) {
        $csvPath = Export-ResultsToCSV -AllRecords $result.AllRecords -OutputPath $OutputPath -Domain $domain
    }
    
    # Generate HTML report
    if ($GenerateHTMLReport) {
        try {
            $reportPath = Create-ComprehensiveHTMLReport -Domain $domain -AllRecords $result.AllRecords -ValidationResults $result.Validations -OutputPath $OutputPath
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-ColorOutput "❌ Error generating HTML report for $domain : $errorMessage" "Red"
        }
    }
}

# Final summary
Write-ColorOutput "" "White"
Write-ColorOutput "🎉 ANALYSIS COMPLETE" "Green"
Write-ColorOutput "===================" "Green"
Write-ColorOutput "Domains Processed: $($Global:AllDomainResults.Count)" "Cyan"
$totalRecords = ($Global:AllDomainResults | ForEach-Object { $_.TotalRecords } | Measure-Object -Sum).Sum
Write-ColorOutput "Total Records Found: $totalRecords" "Cyan"
Write-ColorOutput "Reports Generated in: $OutputPath" "Cyan"

# Ask to open HTML report if single domain and HTML report generated
if ($Global:AllDomainResults.Count -eq 1 -and $GenerateHTMLReport -and $reportPath) {
    Write-ColorOutput "" "White"
    $openReport = Read-Host "Would you like to open the HTML report now? (Y/N)"
    if ($openReport -eq "Y" -or $openReport -eq "y") {
        Start-Process $reportPath
    }
}

Write-ColorOutput "" "White"
Write-ColorOutput "✨ Thank you for using the Complete DNS Configuration Checker!" "Green"
