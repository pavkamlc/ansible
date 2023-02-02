$DebugPreference = "SilentlyContinue" # values: "Continue" "SilentlyContinue" 

$printserver = "srv-XXX"

$regexpprintername = "PRN-(EXA)?(RTP)?-.*-C1[4,6](-PCL)?(-PLC)?(-PS)?"
$regexpadd = "^" + $regexpprintername + "$"
$regexpremove = "^\\\\" + $printserver + "\\" + $regexpprintername + "$"
$regexpremoveip = "^10\.1[46]\.{1,3}\d\.{1,3}\d.*"
$regexpremoveforcename = "^\\\\10\.14\.1\.150\\.*"

$OFS = "`r`n"

# Currently logged user
$User = "$env:UserDomain\$env:UserName"

Clear-Host
Write-Host ("Installing permited printers on server`r`n==========================================")

Write-Debug ("User: " + $User)

$serverprinters = Get-Printer -ComputerName $printserver -Full

# Install all permited printers
ForEach($serverprinter in $serverprinters) {

    #MatchRegular?
    if ($serverprinter.Name -notmatch $regexpadd) { 
        continue 
        }

    Write-Debug ("Printer: " + $serverprinter)

    Write-Debug ("======================")

    # all permissions to this printer
    $sddl = ConvertFrom-SddlString -sddl $serverprinter.PermissionSDDL
    $acls = $sddl.DiscretionaryAcl

    ForEach($acl in $acls)  {
        # this user?
        if ($acl.Contains($User)) {
            # permited?
            if($acl.Contains("AccessAllowed")) { 
                Write-Debug ("Printer: " + $serverprinter.Name + " User Found " + $User + " AccessAllowed - ACL:" + $acl)
                $printerpath = "\\" + $printserver + "\" + $serverprinter.Name
                Write-Host ("Install printer $printerpath")
                Add-Printer -ConnectionName "$printerpath"
            }
            else { 
                Write-Debug ("User Found " + $User + " No Access - ACL:" + $acl)
            }
        }
        else {
        Write-Debug ("User Not Found " + $User + " - ACL:" + $acl)
        }
    }
}

$localprinters = Get-Printer -Full

Write-Host ("`r`nRemoving printers with regexp`r`n=========================================")
#MatchForceRemoveName? - old printserver
ForEach($localprinter in $localprinters) {
    $localprintername = $localprinter.Name
    if ($localprintername -match $regexpremoveforcename) { 
        Write-Host ("Force remove printer $localprintername") 
        Remove-Printer $localprintername
        continue
        }
    }

Write-Host ("`r`nRemoving printers on server without permissions`r`n==========================================")
#MatchRemove because permission? - new printserver, but no permissions
ForEach($localprinter in $localprinters) {
    if ($localprinter.Name -match $regexpremove) { 
        $printerpath = $localprinter.Name
        $test = $printerpath -match "^\\\\(?<server>.+)\\(?<printer>.+)$"
        $printershortname = $Matches.printer
        # all permissions to this printer
        $serverprinter = Get-Printer -ComputerName $printserver -Name $printershortname -Full
        $sddl = ConvertFrom-SddlString -sddl $serverprinter.PermissionSDDL
        $acls = $sddl.DiscretionaryAcl

        $permitedprinter = $false
        ForEach($acl in $acls)  {
            # this user?
            if ($acl.Contains($User)) {
                # permited?
                if( $acl.Contains("AccessAllowed")) { 
                    $permitedprinter = $true;
                    }
                }
            }     
        if ($permitedprinter -eq $false) {
            Write-Host ("Remove printer $printerpath") 
            Remove-Printer $localprinter.Name        
            }
        }
    }

Write-Host ("`r`nRemoving printers on old server`r`n==========================================")
#MatchRemoveIP? - without printserver and not application port    
ForEach($localprinter in $localprinters) {
    $localprintername = $localprinter.Name
    Write-Debug $localprintername
    Write-Debug $localprinter.PortName
    if($localprinter.Type -eq 0) {
        $printerport = Get-PrinterPort $localprinter.PortName
        Write-Debug $printerport
        if ($localprintername -notmatch $regexpremove) {
            $printerportname = $printerport.Name
            if ($printerportname -match $regexpremoveip) { 
                Write-Host ("Force remove printer $localprintername with port $printerportname") 
                Remove-Printer $localprintername
                }
            }
        }
    }

Write-Host "`r`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

