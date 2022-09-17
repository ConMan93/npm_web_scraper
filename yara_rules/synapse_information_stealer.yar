rule obfuscation{
   meta:
        date="2022-09-12"
        author="Gerardo Monterroza ID: 001465094 TEAM 3"
        description="Detect Synapse Stealer."
   strings:
        $anydesk = "/AnyDesk/connection_trace.txt" nocase ascii
        $battlenet = "/Battle.net/Battle.net.config" nocase ascii
        $telegram = "/Telegram Desktop/log.txt" nocase ascii
        $parsec = "/Parsec/log.txt" nocase ascii
        $zip = "/synapse.zip" nocase ascii
        $av = "/avs.txt" nocase ascii
      
   
   condition:
        all of them
}


