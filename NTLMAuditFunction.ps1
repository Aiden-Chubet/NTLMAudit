## Get details of NTLM events from Caller Computer
Function Get-NTLMEventDetails {
    $ServerList = 'APP01','FP01','101ES-DC1','DC2', 'DC1'
    Foreach ($Server in $ServerList)
        {
    
            $filterHash4 = @{LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddDays(-3)} 
            $authenticationEvents4 = Get-WinEvent -ComputerName $Server -FilterHashTable $filterHash4 -MaxEvents 100 -ErrorAction 0 | 
            Where-Object {$_.properties[12].value -eq 'NTLM'} |
            Sort-Object -Property TimeCreated -Descending
            $authenticationEvents4 | Select-Object @{Name = "UserName"; Expression = {$_.Properties[5].Value}}, `
                                    @{Name = "TimeStamp"; Expression = {$_.TimeCreated}}, `
                                    @{Name = "LogonType"; Expression = {$_.Properties[10].Value}}, `
                                    @{Name = "LogonProcessName"; Expression = {$_.Properties[11].Value}}, `
                                    @{Name = "Workstation"; Expression = {$_.Properties[13].Value}}, `
                                    @{Name = "ProcessName"; Expression = {$_.Properties[18].Value}}
        }
    }
    ## Test function
    Get-NTLMEventDetails
