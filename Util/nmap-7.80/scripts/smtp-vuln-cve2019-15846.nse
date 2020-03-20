local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"
local stringaux = require "stringaux"

description = [[
Exim before 4.92.2 allows remote attackers to execute arbitrary code
as root via a trailing backslash. The vulnerability is exploitable
by sending a SNI ending in a backslash-null sequence during the initial
TLS handshake. The exploit exists as a POC.
For more details see doc/doc-txt/cve-2019-15846/ in the source code
repository.

Reference:
* http://exim.org/static/doc/security/CVE-2019-15846.txt
* http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00024.html
* http://www.openwall.com/lists/oss-security/2019/09/06/2
* http://www.openwall.com/lists/oss-security/2019/09/06/4
* http://www.openwall.com/lists/oss-security/2019/09/06/5
]]

---
-- @usage
-- nmap --script=smtp-vuln-cve2019-15846 -pT:25,465,587 <host>
--
-- @output
-- PORT    STATE SERVICE
-- 25/tcp  open  smtp
-- | smtp-vuln-cve2019-15846: 
-- |   VULNERABLE:
-- |   Exim heap overflow
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2019-15846
-- |     Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |       Exim before 4.92.2 allows remote attackers to execute arbitrary code as root via a trailing backslash.
-- |     Disclosure date: 2019-09-06
-- |     Extra information:
-- |       Exim version: 4.84_2
-- |     References:
-- |       https://exim.org/static/doc/security/CVE-2019-15846.txt
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15846

author = "deso & pat, based on smtp-vuln-cve2011-1764 by Djalal Harouni"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}


portrule = function (host, port)
  if port.version.product ~= nil and port.version.product ~= "Exim smtpd" then
     return false
  end
  return shortport.port_or_service({25, 465, 587},
              {"smtp", "smtps", "submission"})(host, port)
end

local function smtp_finish(socket, status, msg)
  if socket then
    socket:close()
  end
  return status, msg
end

local function get_exim_banner(response)
  local banner, version
  banner = response:lower():match("%d+%s(.+)")
  if banner and banner:match("exim") then
    raw_version = banner:match("exim%s([0-9%._]+)")
    -- TODO: use of global variable is discouraged
    orig_version = raw_version
    -- if version format is %d%.%d+_%d
    raw1_version = raw_version:gsub("_","")
    if raw1_version == raw_version then
      dict_version = stringaux.strsplit("%.", raw1_version)
      -- if version format is %d%.%d
      if #dict_version == 2 then
        raw1_version = dict_version[1] .. "." .. dict_version[1] .. "0"
      -- if version format is %d%.%d+%.%d
      elseif #dict_version == 3 then
        raw1_version = dict_version[1] .. "." .. dict_version[2] .. dict_version[3]
      end
    end
    version = tonumber(raw1_version)
  end
  return banner, version
end

-- Checks if the Exim server is vulnerable to CVE-2019-15846
local function check_exim(smtp_opts)
  local smtp_server = {}
  local exim_ver_min, exim_ver_max = 4.800, 4.921

  local socket, ret = smtp.connect(smtp_opts.host,
                          smtp_opts.port,
                          {ssl = true,
                          timeout = 20000,
                          recv_before = true,
                          lines = 1})

  if not socket then
    return smtp_finish(nil, socket, ret)
  end

  smtp_server.banner, smtp_server.version = get_exim_banner(ret)
  if not smtp_server.banner then
    return smtp_finish(socket, false,
              'failed to read the SMTP banner.')
  elseif not smtp_server.banner:match("exim") then
    return smtp_finish(socket, false,
              'not a Exim server: NOT VULNERABLE')
  end

  local vuln = smtp_opts.vuln
  vuln.extra_info = {}
  if smtp_server.version then
    if smtp_server.version <= exim_ver_max and
      smtp_server.version >= exim_ver_min then
      vuln.state = vulns.STATE.VULN

      table.insert(vuln.extra_info,
--          string.format("Exim version: %.03f", smtp_server.version))
          string.format("Exim version: " .. orig_version))
    else
      vuln.state = vulns.STATE.NOT_VULN
    end
  end

  return smtp_finish(socket, true)
end

action = function(host, port)
  local smtp_opts = {
    host = host,
    port = port,
    domain = stdnse.get_script_args('smtp.domain') or
              'nmap.scanme.org',
    vuln = {
      title = 'Exim heap overflow',
      IDS = {CVE = 'CVE-2019-15846'},
      risk_factor = "High",
      scores = {
        CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
      },
      description = [[
Exim before 4.92.2 allows remote attackers to execute arbitrary code as root via a trailing backslash.]],
      references = {
        'https://exim.org/static/doc/security/CVE-2019-15846.txt',
      },
      dates = {
        disclosure = {year = '2019', month = '09', day = '06'},
      },
    },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local status, err = check_exim(smtp_opts)
  if not status then
    stdnse.debug1("%s", err)
    return nil
  end
  return report:make_output(smtp_opts.vuln)
end
