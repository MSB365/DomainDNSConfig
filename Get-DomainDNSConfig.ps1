#region Description
<#     
.NOTES
==============================================================================
Created on:         2025/07/09
Created by:         Drago Petrovic
Organization:       MSB365.blog
Filename:           Get-DomainDNSConfig.ps1
Current version:    V1.0     

Find us on:
* Website:         https://www.msb365.blog
* Technet:         https://social.technet.microsoft.com/Profile/MSB365
* LinkedIn:        https://www.linkedin.com/in/drago-petrovic/
* MVP Profile:     https://mvp.microsoft.com/de-de/PublicProfile/5003446
==============================================================================

.SYNOPSIS
    Checks public DNS configuration for a domain with focus on autodiscover settings
.DESCRIPTION
    This script queries public DNS records for a domain and displays the results in PowerShell.
    Optionally generates an HTML report with all DNS settings in a nice overview.
.PARAMETER Domain
    The domain to check DNS configuration for
.PARAMETER GenerateHTMLReport
    Switch to generate an HTML report
.PARAMETER OutputPath
    Path where to save the HTML report (default: current directory)
.EXAMPLE
    .\Get-DomainDNSConfig.ps1 -Domain "contoso.com"
.EXAMPLE
    .\Get-DomainDNSConfig.ps1 -Domain "contoso.com" -GenerateHTMLReport

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
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [switch]$GenerateHTMLReport,
    
    [string]$OutputPath = (Get-Location).Path
)

function Get-DNSRecords {
    param(
        [string]$Domain,
        [string]$RecordType
    )
    
    try {
        $records = Resolve-DnsName -Name $Domain -Type $RecordType -ErrorAction SilentlyContinue
        return $records
    }
    catch {
        return $null
    }
}

function Get-AutodiscoverConfig {
    param([string]$Domain)
    
    $autodiscoverResults = @()
    
    $autodiscoverDomains = @(
        "autodiscover.$Domain",
        "_autodiscover._tcp.$Domain"
    )
    
    foreach ($autoDomain in $autodiscoverDomains) {
        Write-Host "Checking: $autoDomain" -ForegroundColor Yellow
        
        # Check A record
        $aRecord = Get-DNSRecords -Domain $autoDomain -RecordType "A"
        if ($aRecord) {
            $aRecords = $aRecord | Where-Object {$_.Type -eq "A"}
            foreach ($record in $aRecords) {
                $autodiscoverResults += [PSCustomObject]@{
                    Type = "A"
                    Name = $autoDomain
                    Value = $record.IPAddress
                    TTL = $record.TTL
                }
            }
        }
        
        # Check CNAME record
        $cnameRecord = Get-DNSRecords -Domain $autoDomain -RecordType "CNAME"
        if ($cnameRecord) {
            $cnameRecords = $cnameRecord | Where-Object {$_.Type -eq "CNAME"}
            foreach ($record in $cnameRecords) {
                $autodiscoverResults += [PSCustomObject]@{
                    Type = "CNAME"
                    Name = $autoDomain
                    Value = $record.NameHost
                    TTL = $record.TTL
                }
            }
        }
        
        # Check SRV record for _autodiscover._tcp
        if ($autoDomain -like "*_tcp*") {
            $srvRecord = Get-DNSRecords -Domain $autoDomain -RecordType "SRV"
            if ($srvRecord) {
                $srvRecords = $srvRecord | Where-Object {$_.Type -eq "SRV"}
                foreach ($record in $srvRecords) {
                    $srvValue = "Priority: $($record.Priority), Weight: $($record.Weight), Port: $($record.Port), Target: $($record.NameTarget)"
                    $autodiscoverResults += [PSCustomObject]@{
                        Type = "SRV"
                        Name = $autoDomain
                        Value = $srvValue
                        TTL = $record.TTL
                    }
                }
            }
        }
    }
    
    return $autodiscoverResults
}

function Get-AllDNSRecords {
    param([string]$Domain)
    
    $allRecords = @()
    $recordTypes = @("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV")
    
    foreach ($recordType in $recordTypes) {
        Write-Host "Querying $recordType records for $Domain..." -ForegroundColor Cyan
        
        $records = Get-DNSRecords -Domain $Domain -RecordType $recordType
        
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
                    Type = $record.Type
                    Name = $record.Name
                    Value = $value
                    TTL = $record.TTL
                }
            }
        }
    }
    
    return $allRecords
}

function Create-HTMLReport {
    param(
        [string]$Domain,
        [array]$AutodiscoverRecords,
        [array]$AllRecords,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $filename = "DNS-Report-$($Domain.Replace('.', '-'))-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $fullPath = Join-Path $OutputPath $filename
    
    # Create HTML content as array of strings
    $html = @()
    $html += '<!DOCTYPE html>'
    $html += '<html>'
    $html += '<head>'
    $html += "<title>DNS Configuration Report - $Domain</title>"
    $html += '<style>'
    $html += 'body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }'
    $html += '.container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }'
    $html += 'h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }'
    $html += 'h2 { color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 15px; }'
    $html += 'h3 { color: #2980b9; }'
    $html += 'table { width: 100%; border-collapse: collapse; margin: 20px 0; }'
    $html += 'th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }'
    $html += 'th { background-color: #3498db; color: white; font-weight: bold; }'
    $html += 'tr:nth-child(even) { background-color: #f8f9fa; }'
    $html += 'tr:hover { background-color: #e8f4f8; }'
    $html += '.record-type { font-weight: bold; color: #2980b9; }'
    $html += '.timestamp { color: #7f8c8d; font-style: italic; }'
    $html += '.summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }'
    $html += '.no-records { color: #e74c3c; font-style: italic; }'
    $html += '.value-cell { max-width: 400px; word-wrap: break-word; }'
    $html += '</style>'
    $html += '</head>'
    $html += '<body>'
    $html += '<div class="container">'
    $html += '<h1>DNS Configuration Report</h1>'
    $html += '<div class="summary">'
    $html += "<strong>Domain:</strong> $Domain<br>"
    $html += "<strong>Generated:</strong> <span class='timestamp'>$timestamp</span><br>"
    $html += "<strong>Total Records Found:</strong> $($AllRecords.Count)"
    $html += '</div>'
    
    # Autodiscover section
    $html += '<h2>Autodiscover Configuration</h2>'
    
    if ($AutodiscoverRecords.Count -gt 0) {
        $html += '<table>'
        $html += '<thead>'
        $html += '<tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr>'
        $html += '</thead>'
        $html += '<tbody>'
        
        foreach ($record in $AutodiscoverRecords) {
            $html += '<tr>'
            $html += "<td class='record-type'>$($record.Type)</td>"
            $html += "<td>$($record.Name)</td>"
            $html += "<td class='value-cell'>$($record.Value)</td>"
            $html += "<td>$($record.TTL)</td>"
            $html += '</tr>'
        }
        
        $html += '</tbody>'
        $html += '</table>'
    } else {
        $html += '<p class="no-records">No autodiscover records found.</p>'
    }

    # All DNS records section
    $html += '<h2>All DNS Records</h2>'
    
    if ($AllRecords.Count -gt 0) {
        $groupedRecords = $AllRecords | Group-Object Type | Sort-Object Name
        
        foreach ($group in $groupedRecords) {
            $html += "<h3>$($group.Name) Records</h3>"
            $html += '<table>'
            $html += '<thead>'
            $html += '<tr><th>Name</th><th>Value</th><th>TTL</th></tr>'
            $html += '</thead>'
            $html += '<tbody>'
            
            foreach ($record in $group.Group) {
                $html += '<tr>'
                $html += "<td>$($record.Name)</td>"
                $html += "<td class='value-cell'>$($record.Value)</td>"
                $html += "<td>$($record.TTL)</td>"
                $html += '</tr>'
            }
            
            $html += '</tbody>'
            $html += '</table>'
        }
    } else {
        $html += '<p class="no-records">No DNS records found.</p>'
    }

    $html += '</div>'
    $html += '</body>'
    $html += '</html>'

    # Write HTML to file
    $html -join "`n" | Out-File -FilePath $fullPath -Encoding UTF8
    return $fullPath
}

# Main script execution
Clear-Host
Write-Host "=== DNS Configuration Checker ===" -ForegroundColor Green
Write-Host "Domain: $Domain" -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Green

# Check autodiscover configuration
Write-Host "`nAUTODISCOVER CONFIGURATION" -ForegroundColor Magenta
Write-Host "===========================" -ForegroundColor Magenta

$autodiscoverRecords = Get-AutodiscoverConfig -Domain $Domain

if ($autodiscoverRecords.Count -gt 0) {
    $autodiscoverRecords | Format-Table -AutoSize
    Write-Host "Autodiscover records found: $($autodiscoverRecords.Count)" -ForegroundColor Green
} else {
    Write-Host "No autodiscover records found" -ForegroundColor Red
}

# Get all DNS records
Write-Host "`nALL DNS RECORDS" -ForegroundColor Magenta
Write-Host "===============" -ForegroundColor Magenta

$allRecords = Get-AllDNSRecords -Domain $Domain

if ($allRecords.Count -gt 0) {
    $groupedRecords = $allRecords | Group-Object Type | Sort-Object Name
    
    foreach ($group in $groupedRecords) {
        Write-Host "`n--- $($group.Name) Records ---" -ForegroundColor Yellow
        $group.Group | Format-Table Name, Value, TTL -AutoSize
    }
    
    Write-Host "`nTotal DNS records found: $($allRecords.Count)" -ForegroundColor Green
} else {
    Write-Host "No DNS records found" -ForegroundColor Red
}

# Generate HTML report if requested
if ($GenerateHTMLReport) {
    Write-Host "`nGENERATING HTML REPORT" -ForegroundColor Magenta
    Write-Host "======================" -ForegroundColor Magenta
    
    try {
        $reportPath = Create-HTMLReport -Domain $Domain -AutodiscoverRecords $autodiscoverRecords -AllRecords $allRecords -OutputPath $OutputPath
        Write-Host "HTML report generated successfully!" -ForegroundColor Green
        Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan
        
        $openReport = Read-Host "Would you like to open the HTML report now? (Y/N)"
        if ($openReport -eq "Y" -or $openReport -eq "y") {
            Start-Process $reportPath
        }
    }
    catch {
        Write-Host "Error generating HTML report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== DNS Check Complete ===" -ForegroundColor Green
