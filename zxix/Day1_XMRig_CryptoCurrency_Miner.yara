rule XMRig_CryptoCurrency_Miner {
    meta:
        Description = "Detects XMRig binary on a machine"
        Author = "@zxix"
    strings:
        $text2 = "XMRIG_INCLUDE_RANDOM_MATH" ascii wide fullword
        $text4 = "XMRig" ascii wide fullword
        $text5 = "randomx.xmrig.com" ascii wide
        $text6 = ".config\\xmrig.json" ascii wide fullword
        $text7 = ".xmrig.json" ascii wide fullword
    condition: 
        any of them
}
