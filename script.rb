require 'httparty'

blocklists = ['adguard_ads.txt', 'easylist.txt', 'adguard_privacy.txt', 'easyprivacy.txt', 'adguard_mobile.txt']
discarded_rules = []
total_rules = 0
$dns_blocked = []

readme = []
readme << "The script removes rules that can be blocked by DNS based ad-blocking.\n\n"
readme << "| File | Rules |"
readme << "|:----:|:-----:|"


def adblock_format(blocklist)
  puts blocklist
  HTTParty.get(blocklist).body.each_line do |url|
    if capture = /^(?:\|\|)?([a-zA-Z0-9\.-]+).*/.match(url)
      $dns_blocked << capture[1]
    end
  end
end

def dns_format(blocklist)
  puts blocklist
  HTTParty.get(blocklist).body.each_line do |url|
    if capture = /^(?:0\.0\.0\.0)\s([a-zA-Z0-9\.-]+).*/.match(url)
      $dns_blocked << capture[1]
    end
  end
end

def already_blocked?(url)
  if capture = /^(?:\|\|)?([a-zA-Z0-9\.-]+).*/.match(url)
    return $dns_blocked.include?(capture[1])
  end
  return false
end

adblock_format('https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt') # Adguard DNS
adblock_format('https://big.oisd.nl') # oisd
dns_format('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts') # StevenBlack
dns_format('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt') # hagezi
dns_format('https://hblock.molinero.dev/hosts') # hblock
dns_format('https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt') # 1Hosts
dns_format('https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt') # developerdan
$dns_blocked = $dns_blocked.uniq

blocklists.each do |blocklist|
  selected_rules = []
  File.open(blocklist, "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('!')
      elsif line == ''
      elsif already_blocked?(line)
        discarded_rules << line
      else
        selected_rules << line
      end
    end
  end
  
  File.write(blocklist, selected_rules.join("\n"))
  readme << "| #{blocklist} | #{selected_rules.count} |"
  total_rules += selected_rules.count
end

readme << "| Total | #{total_rules} |"
File.write("discarded.txt", discarded_rules.join("\n"))
File.write("README.md", readme.join("\n"))
