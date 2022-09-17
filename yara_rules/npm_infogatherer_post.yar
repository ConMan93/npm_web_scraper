rule post_request{
   meta:
        data="2022-09-06"
        author="Gerardo Monterroza ID: 001465094 TEAM 3"
        description="Common POST request information gathering attack."
   strings:
        $a="os.homedir()" nocase ascii
        $b="os.hostname()" nocase ascii
        $c="dns.getServers()" nocase ascii
        $d="POST" ascii
      
   
   condition:
        all of them
}
rule urls{
     strings:
          $a="3hlofvn3gdf5bkqxshhx247k1b71vq.oastify.com"
          $b="rni3poh247m6tj110oc9vmi3musngc.burpcollaborator.net"
          $c="quogiq5wvej4o1fe6x3970rhw82yqn.oastify.com"
          $d="cc9qn10kek6cdg4p0ed0h7g7a91nwkic7.oast.pro"
          $e="cc90u7okek6cc7o2hgg0tpcfk8ud8kwnh.oast.me"
          $f="cb5jwgt2vtc00001fjmgggr9rowyyyyy8.interact.sh"
     condition:
          any of them
}