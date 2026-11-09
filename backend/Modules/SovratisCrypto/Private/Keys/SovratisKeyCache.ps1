# Short-lived, process-local cache for key material (byte[]). Entries are zeroed on eviction.
# Key material never goes to environment variables, logs, the pipeline or storage.
$script:SovratisKeyCacheTtlSeconds = 300

function Get-SovratisCachedKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    if (-not $script:SovratisKeyCache) { return $null }
    $Entry = $script:SovratisKeyCache[$Name]
    if (-not $Entry) { return $null }
    if ($Entry.Expires -lt [datetime]::UtcNow) {
        [System.Array]::Clear($Entry.Key, 0, $Entry.Key.Length)
        $script:SovratisKeyCache.Remove($Name)
        return $null
    }
    , $Entry.Key
}

function Set-SovratisCachedKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Key)
    if (-not $script:SovratisKeyCache) { $script:SovratisKeyCache = [hashtable]::Synchronized(@{}) }
    $script:SovratisKeyCache[$Name] = @{ Key = $Key; Expires = [datetime]::UtcNow.AddSeconds($script:SovratisKeyCacheTtlSeconds) }
}

function Clear-SovratisKeyCache {
    [CmdletBinding()]
    param()
    if (-not $script:SovratisKeyCache) { return }
    foreach ($Entry in @($script:SovratisKeyCache.Values)) { [System.Array]::Clear($Entry.Key, 0, $Entry.Key.Length) }
    $script:SovratisKeyCache.Clear()
}
