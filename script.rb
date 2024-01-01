require 'date'
require 'httparty'

def adblock_format(blocklist)
  File.read(blocklist).each_line do |line|
    if capture = /^(?:\|\|)([^\^^!]+)/.match(line.strip)
      $dns_blocked[capture[1].strip] = true
    end
  end
end

def domain_format(blocklist)
  File.read(blocklist).each_line do |line|
    if capture = /^(?:\*\.)?([^#]+)/.match(line.strip)
      $dns_blocked[capture[1].strip] = true
    end
  end
end

def host_format(blocklist)
  File.read(blocklist).each_line do |line|
    if capture = /^(?:0\.0\.0\.0\s)([^#]+)/.match(line.strip)
      $dns_blocked[capture[1].strip] = true
    end
  end
end

def already_blocked?(line)
  if capture = /^(?:@@)?(?:\|\|)?([^#^\^^$^%]+)(.*)/.match(line)
    return false if capture[1].include?(',')
    return true unless capture[1].ascii_only?
    capture[1].split('/')[0].include?('.') ? (domain = capture[1].split('/')[0].split(':')[0]) : (domain = capture[1])
    return false if domain[-1] == '.'
    return false if domain[-1] == '-'
    return false if domain[-1] == '_'
    while domain.index('.') != nil
      return true if $dns_blocked[domain] && !domain.include?('*') && !domain.include?('~')
      domain = domain[(domain.index('.')+1)..-1]
    end
    return true if $dns_blocked[domain]
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
    domains = capture[3].split("|").delete_if {|x| (x[0] == '~') ? already_blocked?(x[1..-1]) : already_blocked?(x) }
    return '' if domains == []
    line = capture[1] + capture[2] + domains.join('|') + capture[4]
  end
  return line
end


$dns_blocked = Hash.new(false)
$temporary_optimization = true
discarded_rules = []
readme = []
readme << "The script removes rules that can be blocked by DNS based ad-blocking.\n\n"
readme << "| File | Original | Modified |"
readme << "|:----:|:-----:|:-----:|"
if $temporary_optimization
  $dns_blocked['facebook.com'] = true
  $dns_blocked['facebook.net'] = true
  $dns_blocked['onion'] = true
end


published_list = []
published_list << ['https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', 'filters/adguard_dns.txt', 'abp']
published_list << ['https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt', 'filters/oisd.txt', 'domain']
published_list << ['https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'filters/stevenblack.txt', 'host']
published_list << ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus.txt', 'filters/hagezi.txt', 'domain']
published_list << ['https://hblock.molinero.dev/hosts_domains.txt', 'filters/hblock.txt', 'domain']
# published_list << ['https://o0.pages.dev/Lite/domains.wildcards', 'filters/1hosts.txt', 'domain']
published_list << ['https://o0.pages.dev/Pro/domains.wildcards', 'filters/1hosts.txt', 'domain']
published_list << ['https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt', 'filters/developerdan.txt', 'host']
published_list.each do |list|
  begin
    response = HTTParty.get(list[0])
    File.write(list[1], response.body) if response.code == 200
  rescue => error
  end
  adblock_format(list[1]) if list[2] == 'abp'
  domain_format(list[1]) if list[2] == 'domain'
  host_format(list[1]) if list[2] == 'host'
end


blocklists = []
blocklists << ['https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt', 'easyprivacy.txt']
# uBlock Origin compatible
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/2.txt', 'adguard_ads_+_easylist_(ublock).txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/3.txt', 'adguard_privacy_(ublock).txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/11.txt', 'adguard_mobile_(ublock).txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/14.txt', 'adguard_annoyances_(ublock).txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/4.txt', 'adguard_social_(ublock).txt']
# AdGuard compatible
blocklists << ['https://filters.adtidy.org/mac_v2/filters/2.txt', 'adguard_ads_+_easylist_(adguard).txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/3.txt', 'adguard_privacy_(adguard).txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/11.txt', 'adguard_mobile_(adguard).txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/14.txt', 'adguard_annoyances_(adguard).txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/4.txt', 'adguard_social_(adguard).txt']
# AdGuard optimized
blocklists << ['https://filters.adtidy.org/extension/safari/filters/2_optimized.txt', 'adguard_ads_+_easylist_(safari).txt']

blocklists.each do |list|
  original_rules = 0
  selected_rules = ["! Title: #{list[1].split('.')[0].split('_').collect{|x| x.capitalize}.join(" ")} Modified"]
  selected_rules << ["! TimeUpdated: #{DateTime.now.new_offset(0).to_s}"]
  selected_rules << ['! Expires: 6 hours (update frequency)']
  selected_rules << ['! Homepage: https://github.com/specter78/adblock']
  response = HTTParty.get(list[0])
  next if response.code != 200
  response.body.each_line do |line|
    original_rules += 1
    line = line.strip
    if line.start_with?('!')
    elsif line == ''
    elsif line.start_with?('/^') || line.start_with?('@@/^')
      selected_rules << line
    elsif $temporary_optimization && /^e?mail[A-Za-z0-9_\.\-]+\$image$/.match(line)
      discarded_rules << line
    elsif already_blocked?(line)
      discarded_rules << line
    else
      selected_rules << additional_domains(line) if (line != '')
    end
  end
  
  File.write(list[1], selected_rules.join("\n"))
  readme << "| #{list[1]} | #{original_rules.count} | #{selected_rules.count} |"
end

# File.write("discarded.txt", discarded_rules.join("\n"))
File.write("README.md", readme.join("\n"))
