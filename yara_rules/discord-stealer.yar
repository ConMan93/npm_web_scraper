
rule discordlofy {
   meta:
      description = "Unspecified malware - file rechnung_3.js"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-24"
      hash1 = "3af15a2d60f946e0c4338c84bd39880652f676dc884057a96a10d7f802215760"
   strings:
      $x1 = "0O347010110&0x463A71D" fullword ascii
   condition:
      all of them
}