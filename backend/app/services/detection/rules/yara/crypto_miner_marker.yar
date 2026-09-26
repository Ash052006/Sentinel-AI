rule Sentry_Crypto_Miner_Marker
{
    meta:
        id = "yara-crypto-miner-v1"
        title = "Cryptocurrency Miner Configuration Markers"
        description = "Detects configuration and installer content referencing common open-source cryptocurrency mining pool protocols and binaries."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "impact"
    strings:
        $stratum = "stratum+tcp://"
        $xmrig = "xmrig"
        $cpuminer = "cpuminer"
        $ethash = "ethash"
        $nicehash = "nicehash"
    condition:
        2 of them
}