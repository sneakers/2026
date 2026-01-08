rule GenesisStealer_ByteSequence {
    meta:
        Description = "Detects an unmodified version of Genesis Stealer"
        Author = "@zxix"
    strings:
        $mz = {4D 5A}
        $s1 = {f58e 8a8d 22bd 75a5 b6a5 6df1 5274 8d05}
        $s2 = {f58d c5ec 0abf 611d 2cfc 9842 3113 9f93}
        $s3 = {f2b5 aab0 68bd b828 7ea9 2878 a085 ae27}
        $s4 = {fe7e ef6d bf7b 76d0 c290 1c1e e897 6664}
    condition: 
        $mz at 0 and all of them
}
