rule powershell_process{
   meta:
        date="2022-09-12"
        author="Gerardo Monterroza ID: 001465094 TEAM 3"
        description="Detect powershell child_process."
   strings:
        $child = "require(\"child_process\")" nocase ascii
        $PS = "powershell" nocase ascii
        $flag1 = "-exec" nocase ascii
        $flag2 = "-EncodedCommand" nocase ascii
        $BP = "bypass" nocase ascii
        $B64 = "Base64EncodedPowerShellCommand" nocase ascii 
   
   condition:
        ($child and $PS) and ($flag1 or $flag2 or $BP or $B64)
}


