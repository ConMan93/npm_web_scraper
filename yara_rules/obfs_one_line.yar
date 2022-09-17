rule obfuscated_one_liner{
   meta:
        date="2022-09-12"
        author="Gerardo Monterroza ID: 001465094 TEAM 3"
        description="Simple obfuscation/one liner detector."
   strings:
        $obfs_var = /var _0x[a-f0-9]{4}/ nocase ascii
		$obfs_const = /const _0x[a-f0-9]{4}/ nocase ascii
		$obfs_let = /let _0x[a-f0-9]{4}/ nocase ascii
		$new_line = /\n/


	condition:
		filesize > 10KB and not $new_line and ($obfs_var or $obfs_const or $obfs_let)
}


