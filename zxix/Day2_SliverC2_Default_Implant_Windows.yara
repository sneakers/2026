rule SliverC2_Default_Implant_Windows {
    meta:
        Description = "Detects a default SliverC2 implant"
        Author = "@zxix"
    strings:
        $mz = {4D 5A}
        $s1 = "GetAmsiBypass" ascii wide
        $s2 = "GetEtwBypass" ascii wide
        $s3 = "GetActiveC2" ascii wide
        $s4 = "GetC2S" ascii wide fullword
    condition: 
        $mz at 0 and all of them
}
