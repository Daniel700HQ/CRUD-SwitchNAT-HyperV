<#
.SYNOPSIS
    Gestor Interactivo CRUD de Switches NAT para Hyper-V con salida a Internet.
.DESCRIPTION
    Script integral que administra de forma atómica y visual la infraestructura
    de conmutadores NAT en Windows e Hyper-V: VMSwitch, IP del Host (vEthernet) y NetNat.
    Diseño visual vertical antifragmentación (Card View y Microtablas compactas).
.NOTES
    Autor                    : [Daniel Oviedo]
    Portfolio / Repositorio  : https://github.com/Daniel700HQ/CRUD-SwitchNAT-HyperV
    SPDX-License-Identifier  : MIT
    Copyright (c) 2026 [Daniel Oviedo (Daniel700HQ)]

    Distribuido bajo la Licencia MIT. El software se proporciona "tal cual",
    sin garantía de ningún tipo. Consulte el archivo LICENSE para más detalles.
#>


#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ==============================================================================
# 1. MOTOR MATEMÁTICO IPv4 SEGURO (ENTEROS DE 64 BITS)
# ==============================================================================

function Convert-IPv4ToInt64 {
    param([string]$IPAddress)
    $octets = $IPAddress.Trim().Split('.')
    if ($octets.Count -ne 4) {
        throw "La dirección IP '$IPAddress' no contiene 4 octetos válidos."
    }
    return ([int64]$octets[0] * 16777216) + ([int64]$octets[1] * 65536) + ([int64]$octets[2] * 256) + [int64]$octets[3]
}

function Convert-Int64ToIPv4 {
    param([int64]$Value)
    $o1 = [math]::Floor($Value / 16777216)
    $rem1 = $Value % 16777216
    $o2 = [math]::Floor($rem1 / 65536)
    $rem2 = $rem1 % 65536
    $o3 = [math]::Floor($rem2 / 256)
    $o4 = $rem2 % 256
    return "$o1.$o2.$o3.$o4"
}

function Get-CidrDetails {
    param([string]$Cidr)

    if ($Cidr -notmatch '^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$') {
        throw "El formato CIDR no es válido. Debe ser del tipo 'X.X.X.X/YY' (ejemplo: 192.168.100.0/24)."
    }

    $parts = $Cidr.Split('/')
    $ipStr = $parts[0]
    $prefix = [int]$parts[1]

    if ($prefix -lt 16 -or $prefix -gt 29) {
        throw "La máscara (/$prefix) debe estar entre /16 y /29 para un entorno virtual NAT estable."
    }

    $totalIPs = [int64][math]::Pow(2, (32 - $prefix))
    $ipInt = Convert-IPv4ToInt64 -IPAddress $ipStr

    $networkInt = [int64]([math]::Floor($ipInt / $totalIPs) * $totalIPs)
    $broadcastInt = [int64]($networkInt + $totalIPs - 1)

    $gatewayInt = [int64]($networkInt + 1)
    $firstVmInt = [int64]($networkInt + 2)
    $lastVmInt  = [int64]($broadcastInt - 1)

    $maskInt = [int64](4294967296 - $totalIPs)
    $subnetMask = Convert-Int64ToIPv4 -Value $maskInt

    return [PSCustomObject]@{
        OriginalCidr     = $Cidr
        PrefixLength     = $prefix
        NetworkAddress   = (Convert-Int64ToIPv4 -Value $networkInt)
        BroadcastAddress = (Convert-Int64ToIPv4 -Value $broadcastInt)
        SubnetMask       = $subnetMask
        GatewayIP        = (Convert-Int64ToIPv4 -Value $gatewayInt)
        FirstVMIP        = (Convert-Int64ToIPv4 -Value $firstVmInt)
        LastVMIP         = (Convert-Int64ToIPv4 -Value $lastVmInt)
        StartInt         = $networkInt
        EndInt           = $broadcastInt
        NormalizedCidr   = "$((Convert-Int64ToIPv4 -Value $networkInt))/$prefix"
    }
}

function Test-IntervalOverlap {
    param(
        [int64]$StartA,
        [int64]$EndA,
        [int64]$StartB,
        [int64]$EndB
    )
    return (($StartA -le $EndB) -and ($StartB -le $EndA))
}

function Test-CidrCollisions {
    param(
        [PSCustomObject]$TargetCidrDetails,
        [string]$ExcludeNatName = $null
    )

    $conflicts = @()

    $existingNats = Get-NetNat -ErrorAction SilentlyContinue
    if ($null -ne $existingNats) {
        foreach ($nat in $existingNats) {
            if ($null -ne $ExcludeNatName -and $nat.Name -eq $ExcludeNatName) {
                continue
            }
            try {
                $natDetails = Get-CidrDetails -Cidr $nat.InternalIPInterfaceAddressPrefix
                if (Test-IntervalOverlap -StartA $TargetCidrDetails.StartInt -EndA $TargetCidrDetails.EndInt -StartB $natDetails.StartInt -EndB $natDetails.EndInt) {
                    $conflicts += "Solapamiento con la regla NetNat activa '$($nat.Name)' ($($nat.InternalIPInterfaceAddressPrefix))."
                }
            } catch {}
        }
    }

    $hostIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { 
        $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" 
    }

    if ($null -ne $hostIPs) {
        foreach ($ipObj in $hostIPs) {
            if ($ipObj.PrefixLength -ge 8 -and $ipObj.PrefixLength -le 32) {
                try {
                    $hDetails = Get-CidrDetails -Cidr "$($ipObj.IPAddress)/$($ipObj.PrefixLength)"
                    if (Test-IntervalOverlap -StartA $TargetCidrDetails.StartInt -EndA $TargetCidrDetails.EndInt -StartB $hDetails.StartInt -EndB $hDetails.EndInt) {
                        $conflicts += "Solapamiento con el adaptador del Host '$($ipObj.InterfaceAlias)' (IP: $($ipObj.IPAddress)/$($ipObj.PrefixLength))."
                    }
                } catch {}
            }
        }
    }

    return $conflicts
}

function Get-NextAvailableSwitchName {
    $existingSwitches = (Get-VMSwitch -ErrorAction SilentlyContinue).Name
    $index = 1
    while ($existingSwitches -contains "NATSwitch$index") {
        $index++
    }
    return "NATSwitch$index"
}

# ==============================================================================
# 2. CONSULTA Y MODELADO DE DATOS (READ)
# ==============================================================================

function Get-UnifiedNatSwitches {
    $switches = Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.SwitchType -eq 'Internal' }
    $allNats = Get-NetNat -ErrorAction SilentlyContinue
    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $allIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $allVMAdapters = Get-VMNetworkAdapter -All -ErrorAction SilentlyContinue

    $results = @()

    foreach ($sw in $switches) {
        $expectedAlias = "vEthernet ($($sw.Name))"
        $adapter = $allAdapters | Where-Object { $_.Name -eq $expectedAlias -or $_.InterfaceDescription -match $sw.Id }

        $ipObj = $null
        if ($null -ne $adapter) {
            $ipObj = $allIPs | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex }
        }

        $expectedNatName = "NAT_$($sw.Name)"
        $natObj = $allNats | Where-Object { $_.Name -eq $expectedNatName }

        if ($null -eq $natObj -and $null -ne $ipObj) {
            foreach ($n in $allNats) {
                try {
                    $d = Get-CidrDetails -Cidr $n.InternalIPInterfaceAddressPrefix
                    $gwInt = Convert-IPv4ToInt64 -IPAddress $ipObj.IPAddress
                    if ($gwInt -ge $d.StartInt -and $gwInt -le $d.EndInt) {
                        $natObj = $n
                        break
                    }
                } catch {}
            }
        }

        $attachedVMs = @()
        if ($null -ne $allVMAdapters) {
            $attachedVMs = ($allVMAdapters | Where-Object { $_.SwitchName -eq $sw.Name }).VMName | Select-Object -Unique
        }

        $health = "Saludable"
        if ($null -eq $adapter) {
            $health = "Falta Adaptador Host"
        } elseif ($null -eq $ipObj) {
            $health = "Falta IP Gateway"
        } elseif ($null -eq $natObj) {
            $health = "Falta Regla NetNat"
        }

        $results += [PSCustomObject]@{
            SwitchName     = $sw.Name
            SwitchId       = $sw.Id
            InterfaceAlias = if ($null -ne $adapter) { $adapter.Name } else { "No encontrado" }
            InterfaceIndex = if ($null -ne $adapter) { $adapter.ifIndex } else { -1 }
            GatewayIP      = if ($null -ne $ipObj) { $ipObj.IPAddress } else { "No asignada" }
            PrefixLength   = if ($null -ne $ipObj) { $ipObj.PrefixLength } else { 0 }
            NatRuleName    = if ($null -ne $natObj) { $natObj.Name } else { "No asignado" }
            SubnetCidr     = if ($null -ne $natObj) { $natObj.InternalIPInterfaceAddressPrefix } else { "Sin NAT" }
            ConnectedVMs   = if ($attachedVMs.Count -gt 0) { ($attachedVMs -join ", ") } else { "Ninguna" }
            HealthStatus   = $health
        }
    }

    return $results
}

# ==============================================================================
# 3. COMPONENTES VISUALES COMPACTOS (CARD VIEW & LISTAS)
# ==============================================================================

function Show-NatSwitchCard {
    param([PSCustomObject]$Switch)

    $statusColor = if ($Switch.HealthStatus -eq "Saludable") { "Green" } else { "Red" }
    $borderLength = 65
    $title = " [ $($Switch.SwitchName) ] "
    $paddingRight = [math]::Max(5, ($borderLength - $title.Length - 2))
    $topBorder = "┌─" + $title + ("─" * $paddingRight) + "┐"
    $bottomBorder = "└" + ("─" * ($topBorder.Length - 2)) + "┘"

    Write-Host $topBorder -ForegroundColor Cyan
    
    Write-Host "│  " -NoNewline -ForegroundColor Cyan
    Write-Host "Estado           : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($Switch.HealthStatus)" -ForegroundColor $statusColor

    Write-Host "│  " -NoNewline -ForegroundColor Cyan
    Write-Host "IP Gateway (Host): " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($Switch.GatewayIP) (/$($Switch.PrefixLength))" -ForegroundColor White

    Write-Host "│  " -NoNewline -ForegroundColor Cyan
    Write-Host "Subred NAT       : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($Switch.SubnetCidr)" -ForegroundColor Yellow

    Write-Host "│  " -NoNewline -ForegroundColor Cyan
    Write-Host "Regla NetNat     : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($Switch.NatRuleName)" -ForegroundColor White

    Write-Host "│  " -NoNewline -ForegroundColor Cyan
    Write-Host "Adaptador Host   : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($Switch.InterfaceAlias) [ID: $($Switch.InterfaceIndex)]" -ForegroundColor White

    Write-Host "│  " -NoNewline -ForegroundColor Cyan
    Write-Host "VMs Conectadas   : " -NoNewline -ForegroundColor DarkGray
    $vmColor = if ($Switch.ConnectedVMs -eq "Ninguna") { "Gray" } else { "Green" }
    Write-Host "$($Switch.ConnectedVMs)" -ForegroundColor $vmColor

    Write-Host $bottomBorder -ForegroundColor Cyan
    Write-Host ""
}

function Show-NatSwitchCompactList {
    param([array]$Switches)

    Write-Host "  #   Switch               Subred               Estado" -ForegroundColor Yellow
    Write-Host " ---  -------------------- -------------------- ---------" -ForegroundColor DarkGray

    for ($i = 0; $i -lt $Switches.Count; $i++) {
        $sw = $Switches[$i]
        $idxStr = "[$($i + 1)]".PadRight(5)
        $nameStr = $sw.SwitchName.PadRight(21)
        $subStr = $sw.SubnetCidr.PadRight(21)
        $statusColor = if ($sw.HealthStatus -eq "Saludable") { "Green" } else { "Red" }

        Write-Host " $idxStr" -NoNewline -ForegroundColor Cyan
        Write-Host "$nameStr$subStr" -NoNewline -ForegroundColor White
        Write-Host "$($sw.HealthStatus)" -ForegroundColor $statusColor
    }
    Write-Host ""
}

function Resolve-SwitchSelection {
    param(
        [array]$Switches,
        [string]$PromptMessage = "Seleccione el número [#] o escriba el nombre del Switch"
    )

    $inputVal = (Read-Host "`n$PromptMessage").Trim()
    if ([string]::IsNullOrWhiteSpace($inputVal)) { return $null }

    if ($inputVal -match '^\d+$') {
        $idx = [int]$inputVal - 1
        if ($idx -ge 0 -and $idx -lt $Switches.Count) {
            return $Switches[$idx].SwitchName
        }
    }

    $match = $Switches | Where-Object { $_.SwitchName -eq $inputVal }
    if ($null -ne $match) {
        return $match.SwitchName
    }

    return $null
}

# ==============================================================================
# 4. ORQUESTADORES CRUD (CREATE, UPDATE, DELETE, REPAIR)
# ==============================================================================

function Wait-ForVirtualAdapter {
    param(
        [string]$SwitchName,
        [int]$TimeoutSeconds = 15
    )
    $expectedAlias = "vEthernet ($SwitchName)"
    $waited = 0
    while ($waited -lt ($TimeoutSeconds * 2)) {
        $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $expectedAlias }
        if ($null -ne $adapter) {
            return $adapter
        }
        Start-Sleep -Milliseconds 500
        $waited++
    }
    return $null
}

function New-UnifiedNatSwitch {
    param(
        [string]$Name,
        [string]$SubnetCidr
    )

    Write-Host "`n[+] Analizando parámetros y comprobando colisiones..." -ForegroundColor Cyan

    $cidrDetails = Get-CidrDetails -Cidr $SubnetCidr
    $expectedNatName = "NAT_$Name"

    $switchExists = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $switchExists) {
        throw "Ya existe un conmutador de Hyper-V con el nombre '$Name'. Use otro nombre (ejemplo: $(Get-NextAvailableSwitchName))."
    }

    $natExists = Get-NetNat -Name $expectedNatName -ErrorAction SilentlyContinue
    if ($null -ne $natExists) {
        throw "Ya existe una regla NetNat en Windows con el nombre '$expectedNatName'. Elimínela o use otro nombre."
    }

    $allHostIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $ipInUse = $allHostIPs | Where-Object { $_.IPAddress -eq $cidrDetails.GatewayIP }
    if ($null -ne $ipInUse) {
        throw "La IP de Gateway '$($cidrDetails.GatewayIP)' ya está en uso en la tarjeta '$($ipInUse[0].InterfaceAlias)'."
    }

    $collisions = Test-CidrCollisions -TargetCidrDetails $cidrDetails
    if ($collisions.Count -gt 0) {
        $msg = "Se detectaron colisiones de red que romperían la conexión:`n"
        foreach ($c in $collisions) { $msg += "  * $c`n" }
        throw $msg
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $existingNatsCount = (Get-NetNat -ErrorAction SilentlyContinue).Count
    if ($os.ProductType -eq 1 -and $existingNatsCount -ge 1) {
        Write-Host "`n[!] AVISO: Está ejecutando Windows Cliente ($($os.Caption))." -ForegroundColor Yellow
        Write-Host "    Windows 10/11 admite formalmente una sola regla NetNat activa a la vez.`n" -ForegroundColor Yellow
        $continueAnyway = Read-Host "¿Desea intentar crearlo de todos modos? (S/N)"
        if ($continueAnyway -ne 'S' -and $continueAnyway -ne 's') {
            Write-Host "[-] Creación cancelada por el usuario." -ForegroundColor Yellow
            return
        }
    }

    $stepSwitchCreated = $false
    $stepIpAssigned = $false
    $assignedIfIndex = $null

    try {
        Write-Host "[1/3] Creando conmutador interno Hyper-V: '$Name'..." -ForegroundColor Cyan
        $null = New-VMSwitch -Name $Name -SwitchType Internal
        $stepSwitchCreated = $true

        Write-Host "      Esperando registro del adaptador en Windows..." -ForegroundColor Gray
        $adapter = Wait-ForVirtualAdapter -SwitchName $Name
        if ($null -eq $adapter) {
            throw "El adaptador 'vEthernet ($Name)' tardó demasiado en registrarse en el sistema."
        }
        $assignedIfIndex = $adapter.ifIndex

        Write-Host "[2/3] Asignando IP Gateway ($($cidrDetails.GatewayIP)/$($cidrDetails.PrefixLength)) al Host..." -ForegroundColor Cyan
        $null = New-NetIPAddress -IPAddress $cidrDetails.GatewayIP `
                                 -PrefixLength $cidrDetails.PrefixLength `
                                 -InterfaceIndex $assignedIfIndex
        $stepIpAssigned = $true

        Write-Host "[3/3] Creando regla de traducción NetNat ('$expectedNatName')..." -ForegroundColor Cyan
        $null = New-NetNat -Name $expectedNatName -InternalIPInterfaceAddressPrefix $cidrDetails.NormalizedCidr

        Write-Host "`n===================================================================" -ForegroundColor Green
        Write-Host " [OK] Conmutador NAT '$Name' creado exitosamente con salida a Internet." -ForegroundColor Green
        Write-Host "===================================================================" -ForegroundColor Green
        Write-Host "  IP Puerta de Enlace (Host): $($cidrDetails.GatewayIP)" -ForegroundColor Yellow
        Write-Host "  Rango para sus VMs         : $($cidrDetails.FirstVMIP) - $($cidrDetails.LastVMIP)" -ForegroundColor Yellow
        Write-Host "  Máscara de Red             : $($cidrDetails.SubnetMask) (/$($cidrDetails.PrefixLength))" -ForegroundColor Yellow
        Write-Host "  DNS para las VMs           : 1.1.1.1 o 8.8.8.8" -ForegroundColor Yellow
        Write-Host "===================================================================" -ForegroundColor Green

    } catch {
        Write-Host "`n[ERROR EN LA CREACIÓN] $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[*] Ejecutando protocolo de reversión (Rollback)..." -ForegroundColor Yellow

        if ($stepIpAssigned -and $null -ne $assignedIfIndex) {
            Remove-NetIPAddress -InterfaceIndex $assignedIfIndex -IPAddress $cidrDetails.GatewayIP -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($stepSwitchCreated) {
            Remove-VMSwitch -Name $Name -Force -ErrorAction SilentlyContinue
        }

        Write-Host "[*] Reversión finalizada. El sistema no guardó cambios a medias." -ForegroundColor Yellow
        throw $_
    }
}

function Remove-UnifiedNatSwitch {
    param([string]$Name)

    $all = Get-UnifiedNatSwitches
    $target = $all | Where-Object { $_.SwitchName -eq $Name }

    if ($null -eq $target) {
        throw "No se encontró ningún conmutador NAT con el nombre '$Name'."
    }

    if ($target.ConnectedVMs -ne "Ninguna") {
        Write-Host "`n[!] ATENCIÓN: Las siguientes VMs están conectadas a este switch:" -ForegroundColor Yellow
        Write-Host "    $($target.ConnectedVMs)" -ForegroundColor Yellow
        Write-Host "    Al eliminarlo, perderán de inmediato la conexión de red." -ForegroundColor Yellow
    }

    $confirm = Read-Host "`n¿Confirma la destrucción total del switch, su IP y su regla NAT? (S/N)"
    if ($confirm -ne 'S' -and $confirm -ne 's') {
        Write-Host "[-] Operación cancelada." -ForegroundColor Yellow
        return
    }

    Write-Host "`n[+] Eliminando componentes en orden seguro..." -ForegroundColor Cyan

    if ($target.NatRuleName -ne "No asignado") {
        $mappings = Get-NetNatStaticMapping -NatName $target.NatRuleName -ErrorAction SilentlyContinue
        if ($null -ne $mappings) {
            foreach ($map in $mappings) {
                Remove-NetNatStaticMapping -NatName $target.NatRuleName -StaticMappingID $map.StaticMappingID -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        Write-Host "[-] Eliminando regla NetNat: '$($target.NatRuleName)'..." -ForegroundColor Gray
        Remove-NetNat -Name $target.NatRuleName -Confirm:$false -ErrorAction SilentlyContinue
    }

    if ($target.InterfaceIndex -ne -1 -and $target.GatewayIP -ne "No asignada") {
        Write-Host "[-] Retirando IP Gateway ($($target.GatewayIP))..." -ForegroundColor Gray
        Remove-NetIPAddress -InterfaceIndex $target.InterfaceIndex -IPAddress $target.GatewayIP -Confirm:$false -ErrorAction SilentlyContinue
    }

    Write-Host "[-] Eliminando conmutador Hyper-V: '$($target.SwitchName)'..." -ForegroundColor Gray
    Remove-VMSwitch -Name $target.SwitchName -Force -ErrorAction SilentlyContinue

    Write-Host "`n[OK] Switch NAT eliminado por completo." -ForegroundColor Green
}

function Set-UnifiedNatSwitchSubnet {
    param(
        [string]$Name,
        [string]$NewSubnetCidr
    )

    $all = Get-UnifiedNatSwitches
    $target = $all | Where-Object { $_.SwitchName -eq $Name }

    if ($null -eq $target) {
        throw "No se encontró el conmutador NAT con el nombre '$Name'."
    }

    $newDetails = Get-CidrDetails -Cidr $NewSubnetCidr

    $collisions = Test-CidrCollisions -TargetCidrDetails $newDetails -ExcludeNatName $target.NatRuleName
    if ($collisions.Count -gt 0) {
        $msg = "La nueva subred genera colisiones:`n"
        foreach ($c in $collisions) { $msg += "  * $c`n" }
        throw $msg
    }

    Write-Host "`n[+] Reconfigurando la capa NAT para '$Name'..." -ForegroundColor Cyan

    if ($target.NatRuleName -ne "No asignado") {
        Write-Host "[-] Eliminando regla NAT actual ($($target.NatRuleName))..." -ForegroundColor Gray
        Remove-NetNat -Name $target.NatRuleName -Confirm:$false
    }

    if ($target.InterfaceIndex -ne -1 -and $target.GatewayIP -ne "No asignada") {
        Write-Host "[-] Retirando IP Gateway anterior ($($target.GatewayIP))..." -ForegroundColor Gray
        Remove-NetIPAddress -InterfaceIndex $target.InterfaceIndex -IPAddress $target.GatewayIP -Confirm:$false
    }

    Write-Host "[+] Asignando nueva IP Gateway ($($newDetails.GatewayIP)/$($newDetails.PrefixLength))..." -ForegroundColor Gray
    $null = New-NetIPAddress -InterfaceIndex $target.InterfaceIndex -IPAddress $newDetails.GatewayIP -PrefixLength $newDetails.PrefixLength

    $newNatName = "NAT_$Name"
    Write-Host "[+] Creando regla NetNat actualizada ($($newDetails.NormalizedCidr))..." -ForegroundColor Gray
    $null = New-NetNat -Name $newNatName -InternalIPInterfaceAddressPrefix $newDetails.NormalizedCidr

    Write-Host "`n[OK] Subred actualizada exitosamente." -ForegroundColor Green
}

function Repair-UnifiedNatOrphans {
    Write-Host "`n[+] Analizando reglas NAT y objetos residuales..." -ForegroundColor Cyan

    $switches = (Get-VMSwitch -SwitchType Internal -ErrorAction SilentlyContinue).Name
    $nats = Get-NetNat -ErrorAction SilentlyContinue

    $orphans = @()
    if ($null -ne $nats) {
        foreach ($n in $nats) {
            if ($n.Name -like "NAT_*") {
                $expectedSwitch = $n.Name.Substring(4)
                if ($switches -notcontains $expectedSwitch) {
                    $orphans += $n
                }
            }
        }
    }

    if ($orphans.Count -eq 0) {
        Write-Host "[OK] No se detectaron reglas NAT huérfanas en el sistema." -ForegroundColor Green
        return
    }

    Write-Host "`n[!] Reglas NetNat huérfanas detectadas (sin switch Hyper-V asociado):" -ForegroundColor Yellow
    $orphans | Select-Object Name, InternalIPInterfaceAddressPrefix | Format-Table -AutoSize

    $opt = Read-Host "¿Desea eliminar estas reglas huérfanas para liberar sus subredes? (S/N)"
    if ($opt -eq 'S' -or $opt -eq 's') {
        foreach ($on in $orphans) {
            Write-Host "[-] Eliminando regla: $($on.Name)..." -ForegroundColor Gray
            Remove-NetNat -Name $on.Name -Confirm:$false
        }
        Write-Host "[OK] Limpieza de huérfanos completada." -ForegroundColor Green
    }
}

# ==============================================================================
# 5. GESTIÓN DE MAPEO DE PUERTOS (PORT FORWARDING)
# ==============================================================================

function Manage-PortForwarding {
    param([string]$SwitchName)

    $all = Get-UnifiedNatSwitches
    $target = $all | Where-Object { $_.SwitchName -eq $SwitchName }

    if ($null -eq $target -or $target.NatRuleName -eq "No asignado") {
        throw "El conmutador '$SwitchName' no cuenta con una regla NetNat activa."
    }

    while ($true) {
        Clear-Host
        Write-Host "===================================================================" -ForegroundColor DarkCyan
        Write-Host "      REENVÍO DE PUERTOS (PORT FORWARDING) - SWITCH: $SwitchName" -ForegroundColor Cyan
        Write-Host "      Regla: $($target.NatRuleName) | Subred: $($target.SubnetCidr)" -ForegroundColor Gray
        Write-Host "===================================================================" -ForegroundColor DarkCyan

        $currentRules = Get-NetNatStaticMapping -NatName $target.NatRuleName -ErrorAction SilentlyContinue

        if ($null -ne $currentRules -and @($currentRules).Count -gt 0) {
            Write-Host "`nReglas de reenvío configuradas:" -ForegroundColor Yellow
            @($currentRules) | Select-Object StaticMappingID, Protocol, ExternalPort, InternalIPAddress, InternalPort | Format-Table -AutoSize
        } else {
            Write-Host "`nNo hay puertos redirigidos hacia las VMs." -ForegroundColor Gray
        }

        Write-Host "`n [1] Agregar nueva redirección de puerto"
        Write-Host " [2] Eliminar una redirección existente"
        Write-Host " [0] Volver al menú principal"
        Write-Host "===================================================================" -ForegroundColor DarkCyan
        $subOpt = Read-Host "Seleccione una opción"

        switch ($subOpt) {
            "1" {
                try {
                    Write-Host "`n--- Crear redirección ---" -ForegroundColor Cyan
                    $protoInput = Read-Host "Protocolo (TCP / UDP) [Por defecto: TCP]"
                    $protocol = if ([string]::IsNullOrWhiteSpace($protoInput)) { "TCP" } else { $protoInput.Trim().ToUpper() }

                    if ($protocol -ne "TCP" -and $protocol -ne "UDP") {
                        throw "Protocolo no válido. Solo se admite TCP o UDP."
                    }

                    $extPort = [int](Read-Host "Puerto Externo en el Host (ejemplo: 8080)")
                    $vmIP = (Read-Host "IP interna de la Máquina Virtual (ejemplo: 192.168.100.15)").Trim()
                    $intPort = [int](Read-Host "Puerto Interno en la Máquina Virtual (ejemplo: 80)")

                    $null = Add-NetNatStaticMapping -NatName $target.NatRuleName `
                                                    -Protocol $protocol `
                                                    -ExternalIPAddressPrefix "0.0.0.0/0" `
                                                    -ExternalPort $extPort `
                                                    -InternalIPAddress $vmIP `
                                                    -InternalPort $intPort

                    Write-Host "`n[OK] Redirección creada: Host:$extPort -> VM $vmIP`:$intPort ($protocol)" -ForegroundColor Green
                } catch {
                    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                }
                Read-Host "`nPresione Enter para continuar..."
            }
            "2" {
                if ($null -ne $currentRules -and @($currentRules).Count -gt 0) {
                    $id = [int](Read-Host "`nIngrese el StaticMappingID de la regla a eliminar")
                    try {
                        Remove-NetNatStaticMapping -NatName $target.NatRuleName -StaticMappingID $id -Confirm:$false
                        Write-Host "[OK] Regla eliminada." -ForegroundColor Green
                    } catch {
                        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "`nNo existen reglas para eliminar." -ForegroundColor Yellow
                }
                Read-Host "`nPresione Enter para continuar..."
            }
            "0" { return }
        }
    }
}

# ==============================================================================
# 6. GUÍA DE CONFIGURACIÓN PARA MÁQUINAS VIRTUALES
# ==============================================================================

function Show-VmConfigGuide {
    param([string]$SwitchName)

    $all = Get-UnifiedNatSwitches
    $target = $all | Where-Object { $_.SwitchName -eq $SwitchName }

    if ($null -eq $target -or $target.SubnetCidr -eq "Sin NAT") {
        throw "El conmutador especificado no tiene una subred NAT activa."
    }

    $details = Get-CidrDetails -Cidr $target.SubnetCidr

    Clear-Host
    Write-Host "===================================================================" -ForegroundColor DarkGreen
    Write-Host "        GUÍA DE CONFIGURACIÓN DE RED PARA MÁQUINAS VIRTUALES" -ForegroundColor Green
    Write-Host "        Switch: $SwitchName | Subred: $($target.SubnetCidr)" -ForegroundColor Gray
    Write-Host "===================================================================" -ForegroundColor DarkGreen
    Write-Host "`nConfigure estos parámetros en el adaptador de red dentro de su VM:`n"
    Write-Host "  Dirección IP VM    : " -NoNewline; Write-Host "$($details.FirstVMIP)  hasta  $($details.LastVMIP)" -ForegroundColor Yellow
    Write-Host "  Máscara de Subred  : " -NoNewline; Write-Host "$($details.SubnetMask) (/$($details.PrefixLength))" -ForegroundColor Yellow
    Write-Host "  Puerta de Enlace   : " -NoNewline; Write-Host "$($details.GatewayIP) (IP del Host)" -ForegroundColor Yellow
    Write-Host "  DNS Primario       : " -NoNewline; Write-Host "1.1.1.1 (Cloudflare) o 8.8.8.8 (Google)" -ForegroundColor Yellow
    Write-Host "  DNS Secundario     : " -NoNewline; Write-Host "1.0.0.1 o 8.8.4.4" -ForegroundColor Yellow

    Write-Host "`n--- Comandos listos para copiar y pegar dentro de la VM ---" -ForegroundColor Cyan
    Write-Host "[Windows PowerShell como Administrador]:" -ForegroundColor Gray
    Write-Host "New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress $($details.FirstVMIP) -PrefixLength $($details.PrefixLength) -DefaultGateway $($details.GatewayIP)" -ForegroundColor DarkYellow
    Write-Host "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 1.1.1.1, 8.8.8.8" -ForegroundColor DarkYellow

    Write-Host "`n[Linux Netplan (/etc/netplan/01-net.yaml)]:" -ForegroundColor Gray
    Write-Host "addresses: [$($details.FirstVMIP)/$($details.PrefixLength)]`ngateway4: $($details.GatewayIP)`nnameservers:`n  addresses: [1.1.1.1, 8.8.8.8]" -ForegroundColor DarkYellow
    Write-Host "===================================================================" -ForegroundColor DarkGreen
}

# ==============================================================================
# 7. MENÚ PRINCIPAL INTERACTIVO
# ==============================================================================

function Start-HyperVNatManager {
    while ($true) {
        Clear-Host
        $os = Get-CimInstance Win32_OperatingSystem
        $nats = Get-NetNat -ErrorAction SilentlyContinue
        $natCount = if ($null -ne $nats) { @($nats).Count } else { 0 }
        $osMode = if ($os.ProductType -eq 1) { "Windows Cliente (Máx. 1 NAT)" } else { "Windows Server" }

        Write-Host "===================================================================" -ForegroundColor Cyan
        Write-Host "       GESTOR DE CONMUTADORES NAT PARA HYPER-V (INTERNET READY)" -ForegroundColor White
        Write-Host "===================================================================" -ForegroundColor Cyan
        Write-Host " [Host: $($env:COMPUTERNAME) | NATs Activos: $natCount | Entorno: $osMode]" -ForegroundColor DarkGray
        Write-Host "===================================================================" -ForegroundColor Cyan

        Write-Host "`n  [1] Listar conmutadores NAT y estado (Read)"
        Write-Host "  [2] Crear nuevo conmutador NAT con salida a Internet (Create)"
        Write-Host "  [3] Modificar subred de un conmutador existente (Update)"
        Write-Host "  [4] Administrar reenvío de puertos / Port Forwarding (Update)"
        Write-Host "  [5] Eliminar conmutador NAT por completo (Delete)"
        Write-Host "  [6] Diagnóstico y reparación de recursos huérfanos"
        Write-Host "  [7] Ver guía de configuración IP/DNS para las VMs"
        Write-Host "`n  [0] Salir"
        Write-Host "===================================================================" -ForegroundColor Cyan

        $option = Read-Host "`nSeleccione una opción"

        switch ($option) {
            "1" {
                Clear-Host
                Write-Host "--- Inventario de Conmutadores NAT Hyper-V ---`n" -ForegroundColor Cyan
                $switches = Get-UnifiedNatSwitches

                if ($switches.Count -eq 0) {
                    Write-Host "No se encontraron conmutadores virtuales internos configurados." -ForegroundColor Yellow
                } else {
                    foreach ($sw in $switches) {
                        Show-NatSwitchCard -Switch $sw
                    }
                }
                Read-Host "`nPresione Enter para volver al menú principal..."
            }

            "2" {
                Clear-Host
                Write-Host "--- Asistente de Creación de Conmutador NAT ---`n" -ForegroundColor Cyan

                $suggestedName = Get-NextAvailableSwitchName
                $nameInput = Read-Host "Nombre para el conmutador [Por defecto: $suggestedName]"
                $switchName = if ([string]::IsNullOrWhiteSpace($nameInput)) { $suggestedName } else { $nameInput.Trim() }

                $subnetInput = Read-Host "Prefijo de red CIDR [Por defecto: 192.168.100.0/24]"
                $subnetCidr = if ([string]::IsNullOrWhiteSpace($subnetInput)) { "192.168.100.0/24" } else { $subnetInput.Trim() }

                try {
                    New-UnifiedNatSwitch -Name $switchName -SubnetCidr $subnetCidr
                } catch {
                    Write-Host "`n[ERROR AL CREAR] $($_.Exception.Message)" -ForegroundColor Red
                }
                Read-Host "`nPresione Enter para volver al menú principal..."
            }

            "3" {
                Clear-Host
                Write-Host "--- Modificación de Subred ---`n" -ForegroundColor Cyan
                $switches = Get-UnifiedNatSwitches

                if ($switches.Count -eq 0) {
                    Write-Host "No hay conmutadores disponibles." -ForegroundColor Yellow
                } else {
                    Show-NatSwitchCompactList -Switches $switches
                    $targetName = Resolve-SwitchSelection -Switches $switches

                    if ($null -ne $targetName) {
                        $newSubnet = (Read-Host "Nuevo prefijo CIDR (ejemplo: 192.168.120.0/24)").Trim()
                        try {
                            Set-UnifiedNatSwitchSubnet -Name $targetName -NewSubnetCidr $newSubnet
                        } catch {
                            Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "`n[!] Selección no válida o cancelada." -ForegroundColor Yellow
                    }
                }
                Read-Host "`nPresione Enter para volver al menú principal..."
            }

            "4" {
                Clear-Host
                Write-Host "--- Administración de Port Forwarding ---`n" -ForegroundColor Cyan
                $switches = Get-UnifiedNatSwitches

                if ($switches.Count -eq 0) {
                    Write-Host "No hay conmutadores disponibles." -ForegroundColor Yellow
                    Read-Host "`nPresione Enter para volver al menú principal..."
                } else {
                    Show-NatSwitchCompactList -Switches $switches
                    $targetName = Resolve-SwitchSelection -Switches $switches

                    if ($null -ne $targetName) {
                        try {
                            Manage-PortForwarding -SwitchName $targetName
                        } catch {
                            Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                            Read-Host "`nPresione Enter para volver al menú principal..."
                        }
                    } else {
                        Write-Host "`n[!] Selección no válida o cancelada." -ForegroundColor Yellow
                        Read-Host "`nPresione Enter para volver al menú principal..."
                    }
                }
            }

            "5" {
                Clear-Host
                Write-Host "--- Eliminación de Conmutador NAT ---`n" -ForegroundColor Cyan
                $switches = Get-UnifiedNatSwitches

                if ($switches.Count -eq 0) {
                    Write-Host "No hay conmutadores para eliminar." -ForegroundColor Yellow
                } else {
                    Show-NatSwitchCompactList -Switches $switches
                    $targetName = Resolve-SwitchSelection -Switches $switches

                    if ($null -ne $targetName) {
                        try {
                            Remove-UnifiedNatSwitch -Name $targetName
                        } catch {
                            Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "`n[!] Selección no válida o cancelada." -ForegroundColor Yellow
                    }
                }
                Read-Host "`nPresione Enter para volver al menú principal..."
            }

            "6" {
                Clear-Host
                Repair-UnifiedNatOrphans
                Read-Host "`nPresione Enter para volver al menú principal..."
            }

            "7" {
                Clear-Host
                Write-Host "--- Guía de Red para VMs ---`n" -ForegroundColor Cyan
                $switches = Get-UnifiedNatSwitches

                if ($switches.Count -eq 0) {
                    Write-Host "No hay conmutadores disponibles." -ForegroundColor Yellow
                } else {
                    Show-NatSwitchCompactList -Switches $switches
                    $targetName = Resolve-SwitchSelection -Switches $switches

                    if ($null -ne $targetName) {
                        try {
                            Show-VmConfigGuide -SwitchName $targetName
                        } catch {
                            Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "`n[!] Selección no válida o cancelada." -ForegroundColor Yellow
                    }
                }
                Read-Host "`nPresione Enter para volver al menú principal..."
            }

            "0" {
                Clear-Host
                Write-Host "Gestor finalizado." -ForegroundColor Cyan
                return
            }

            Default {
                Write-Host "`nOpción no válida." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ==============================================================================
# 8. EJECUCIÓN
# ==============================================================================
Start-HyperVNatManager
