rule obfuscation{
   meta:
        date="2022-09-12"
        author="Gerardo Monterroza ID: 001465094 TEAM 3"
        description="Detect javascript-obfuscation require."
   strings:
        $a="javascript-obfuscator" nocase ascii
        $a2="uglyfijs" nocase ascii
        $b="base64" nocase ascii
        $c="crypto" nocase ascii
        $d="path" ascii
      
   
   condition:
        ($a or $a2) and ($b or $c or $d)
}