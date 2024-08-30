# PowerShell Script for macOS with Options to Skip Ping and NSLookup

function Get-Geolocation {
    param (
        [string]$ip
    )

    try {
        $geoResult = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -UseBasicParsing
        if ($geoResult.status -eq "success") {
            return "Country: " + $geoResult.country + "`n" +
                   "Region: " + $geoResult.regionName + "`n" +
                   "City: " + $geoResult.city + "`n" +
                   "ISP: " + $geoResult.isp + "`n" +
                   "Latitude: " + $geoResult.lat + "`n" +
                   "Longitude: " + $geoResult.lon
        } else {
            return "Geolocation lookup failed: " + $geoResult.message
        }
    } catch {
        return "Geolocation lookup failed due to an error."
    }
}

# Main script logic
Write-Host "Enter the IP address:"
$ip = Read-Host

if (-not [string]::IsNullOrEmpty($ip)) {
    
    # Option for Ping
    Write-Host "Do you want to perform Ping? (y/n):"
    $doPing = Read-Host
    if ($doPing -eq "y") {
        Write-Host "`nPinging $ip..."
        $pingResult = ping -c 4 $ip 2>&1
        Write-Host $pingResult
    } else {
        Write-Host "Skipping Ping."
    }
    
    # Option for NSLookup
    Write-Host "`nDo you want to perform NSLookup? (y/n):"
    $doNslookup = Read-Host
    if ($doNslookup -eq "y") {
        Write-Host "`nRunning NSLookup on $ip..."
        $nslookupResult = nslookup $ip 2>&1
        Write-Host $nslookupResult
    } else {
        Write-Host "Skipping NSLookup."
    }
    
    # Geolocation Lookup (always performed)
    Write-Host "`nLooking up geolocation for $ip..."
    $geoResult = Get-Geolocation -ip $ip
    Write-Host $geoResult

} else {
    Write-Host "Invalid IP address entered. Please try again."
}