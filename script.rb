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
  HTTParty.get(blocklist).body.each_line do |url|
    next if url.start_with?('!')
    next if url.start_with?('@@')
    next if url == ''
    url = url[2..-1] if url.start_with?('||')
    url = url.split('^').first
    $dns_blocked << url
  end
end

def dns_format(blocklist)
  HTTParty.get(blocklist).body.each_line do |url|
    next unless url.start_with?('0.0.0.0')
    $dns_blocked << url.split(' ')[1]
  end
end

def already_blocked?(url)
  if capture = /^(?:\|\|)?([a-zA-Z0-9][a-zA-Z0-9\.-]+[a-zA-Z0-9])(?:.*)?/.match(url)
    return $dns_blocked.include?(capture[1])
  end
  return false
end

adblock_format('https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt') # Adguard DNS
adblock_format('https://big.oisd.nl') # oisd
dns_format('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts') # StevenBlack
dns_format('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt') # hagezi
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
      
      # elsif /^(\|\|)?(graph\.facebook\.com).*$/.match?(line)
      #   discarded_rules << line
      # elsif /^(\|\|)?(pagead2\.googlesyndication\.com).*$/.match?(line)
      #   discarded_rules << line
      # elsif /^(\|\|)?(www\.)?(googletagmanager\.com).*$/.match?(line)
      #   discarded_rules << line
      # elsif line[0..-2].count('/') > 0 # i.e. '/' does not exist ONLY at the end
        # selected_rules << line
      # elsif (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party') || line.end_with?('^$all') || line.end_with?('^$popup'))
        # discarded_rules << line
      # elsif /^(\|\|)?[a-zA-Z0-9_.]*[a-zA-Z0-9](\^)?(\^\$third-party)?$/.match?(line)
        # discarded_rules << line
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
