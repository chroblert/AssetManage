-- The Head Section --
description = [[Simple script to detect the presence of the vulnerable URL
/cgi-bin/config.exp on Cisco routers which indicates a missing patch for
CVE-2019-1653.]]

---
-- @usage
-- nmap --script cve_2019_1653 -p 443 <target>
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- |_cve_2019_1653: Host vulnerable to CVE-2019-1653!

author = "dubfr33"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local http = require "http"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local uri = "/cgi-bin/config.exp"
    local response = http.get(host, port, uri)

    if response.status == 200 and http.response_contains(response,"sysconfig",false) then
      return "Host vulnerable to CVE-2019-1653!"
    end
end
