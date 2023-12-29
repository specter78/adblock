require 'httparty'

def adblock_format(blocklist)
  File.read(blocklist).each_line do |url|
    if capture = /^(?:\|\|)?([a-zA-Z0-9\.\-_]+).*/.match(url.strip)
      $dns_blocked[capture[1]] = true
    end
  end
end

def dns_format(blocklist)
  File.read(blocklist).each_line do |url|
    if capture = /^(?:0\.0\.0\.0)\s([a-zA-Z0-9\.\-_]+).*/.match(url.strip)
      $dns_blocked[capture[1]] = true
    end
  end
end

def already_blocked?(url)
  if capture = /^(?:@@)?(?:\|\|)?([^#^\^^$^%]+)(.*)/.match(url)
    return false if capture[1].include?(',')
    return true unless capture[1].ascii_only?
    capture[1].split('/')[0].include?('.') ? (domain = capture[1].split('/')[0].split(':')[0]) : (domain = capture[1])
    return false if domain.include?('*')
    return false if domain.include?('~')
    return false if domain[-1] == '.'
    return false if domain[-1] == '-'
    return false if domain[-1] == '_'
    while domain.index('.') != nil
      return true if $dns_blocked[domain]
      domain = domain[(domain.index('.')+1)..-1]
    end
  end
  return false
end

def additional_domains(line)
  # beginning domains
  if capture = /^((?:@@)?(?:\|\|)?)([^#^\^^$^%]+)(.*)/.match(line)
    if capture[2].include?(',')
      domains = capture[2].split(',').delete_if {|x| already_blocked?(x)}
      return '' if domains == []
      (capture[2][-1] == ',') ? (domains = domains.join(',') + ',') : (domains = domains.join(','))
      line = capture[1] + domains + capture[3]
    end
  end
  
  # ending domains
  if capture = /^(.*)(\$domain=)([^#^\^^$^%]+)(.*)/.match(line)
    domains = capture[3].split("|").delete_if {|x| already_blocked?(x)}
    return '' if domains == []
    line = capture[1] + capture[2] + domains.join('|') + capture[4]
  end
  return line
end


discarded_rules = []
total_rules = 0
readme = []
readme << "The script removes rules that can be blocked by DNS based ad-blocking.\n\n"
readme << "| File | Rules |"
readme << "|:----:|:-----:|"
$dns_blocked = Hash.new(false)
$dns_blocked['graph.facebook.com'] = true


published_list = []
published_list << ['https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt', 'filters/adguard_dns.txt', 'adp']
published_list << ['https://big.oisd.nl', 'filters/oisd.txt', 'adp']
published_list << ['https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'filters/stevenblack.txt', 'dns']
published_list << ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt', 'filters/hagezi.txt', 'dns']
published_list << ['https://hblock.molinero.dev/hosts', 'filters/hblock.txt', 'dns']
published_list << ['https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt', 'filters/1hosts.txt', 'dns']
published_list << ['https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt', 'filters/developerdan.txt', 'dns']
published_list.each do |list|
  begin
    response = HTTParty.get(list[0])
    File.write(list[1], response.body) if response.code == 200
  rescue => error
  end
  adblock_format(list[1]) if list[2] == 'adp'
  dns_format(list[1]) if list[2] == 'dns'
end


blocklists = []
blocklists << ['https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt', 'adguard_ads.txt']
blocklists << ['https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt', 'easylist.txt']
blocklists << ['https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt', 'adguard_privacy.txt']
blocklists << ['https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt', 'easyprivacy.txt']
blocklists << ['https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt', 'adguard_mobile.txt']

blocklists.each do |list|
  selected_rules = ["! Title: #{list[1].split('.')[0].split('_').collect{|x| x.capitalize}.join(" ")} Modified"]
  response = HTTParty.get(list[0])
  next if response.code != 200
  response.body.each_line do |line|
    line = line.strip
    if line.start_with?('!')
    elsif line == ''
    elsif line.start_with?('/') || line.start_with?('@@/')
      selected_rules << line
    elsif already_blocked?(line)
      discarded_rules << line
    else
      selected_rules << additional_domains(line) if (line != '')
    end
  end
  
  File.write(list[1], selected_rules.join("\n"))
  readme << "| #{list[1]} | #{selected_rules.count} |"
  total_rules += selected_rules.count
end

readme << "| Total | #{total_rules} |"
File.write("discarded.txt", discarded_rules.join("\n"))
File.write("README.md", readme.join("\n"))
