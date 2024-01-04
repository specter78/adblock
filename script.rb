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
  if capture = /^(?:@@)?(?:\|\|?)?(?:https?)?(?:\:\/\/)?([^#^\^^$^%]+)(.*)/.match(line)
    return false if capture[1].include?(',')
    return true unless capture[1].ascii_only?
    return false if capture[1].index('.') && capture[1].index('/') && (capture[1].index('/') < capture[1].index('.'))
    domain = capture[1].split('/')[0]
    return false if domain[-1] == '.'
    return false if domain[0] == '~'
    return true if /^(?:www\.|translate\.)?google\..*/.match(domain) && (not /.*(?:com|in|\*)$/.match(domain)) && capture[2].start_with?('#') # filter list optimization
    return true if /^([^\.]*)?yandex\.(?:com|\*)$/.match(domain) && capture[2].start_with?('#') # filter list optimization
    return true if /^airfrance\..*/.match(domain) && capture[2].start_with?('#') # filter list optimization
    return true if /^dizipal\d+\.(?:com|cloud)$/.match(domain) && capture[2].start_with?('#') # filter list optimization
    while domain.index('.') != nil
      return true if $dns_blocked[domain] && !domain.include?('*')
      domain = domain[(domain.index('.')+1)..-1]
    end
    return true if $dns_blocked[domain] # tld
  end
  return false
end

def additional_domains(line)
  # beginning domains
  if capture = /^((?:@@)?(?:\|\|)?)([^#^\^^$^%]+)(.*)/.match(line)
    if capture[2].include?(',')
      domains = capture[2].split(',').delete_if {|x| already_blocked?(x+capture[3])}
      return "" if domains == []
      (capture[2][-1] == ',') ? (domains = domains.join(',') + ',') : (domains = domains.join(','))
      line = capture[1] + domains + capture[3]
    end
  end
  
  # ending domains
  if capture = /^(.*)(\$domain=)([^#^\^^$^%]+)(.*)/.match(line)
    domains = capture[3].split("|").delete_if { |x| already_blocked?(x) }
    return "" if domains == []
    line = capture[1] + capture[2] + domains.join('|') + capture[4]
  end
  return line
end


$dns_blocked = Hash.new(false)
discarded_rules = []
readme = []
readme << "The script removes rules that are blocked by DNS based blocking.\n\n"
readme << "| File | Original | Modified |"
readme << "|:----:|:-----:|:-----:|"

# https://en.wikipedia.org/wiki/Country_code_top-level_domain (for annoyances and social)
$tld_optimization = ['ru', 'de', 'jp', 'cn', 'pl', 'tr', 'br', 'fr', 'ua', 'es', 'pt', 'lv', 'ch', 'gr', 'hu', 'by', 'cz', 'nl', 'dk', 'ro', 'no', 'se', 'fi', 'su', 'it', 'kz', 'kg', 'uz', 'tm', 'tj', 'au', 'si', 'hr', 'kr', 'tw', 'sk', 'vn', 'at', 'be', 'id', 'sg']
$domain_optimization = ['facebook.com', 'facebook.net', 'onion'] 
$domain_optimization.each{ |x| $dns_blocked[x] = true } # filter list optimization


published_list = []
published_list << ['https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', 'dns/adguard_dns.txt', 'abp']
published_list << ['https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt', 'dns/oisd.txt', 'domain']
published_list << ['https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'dns/stevenblack.txt', 'host']
published_list << ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus.txt', 'dns/hagezi.txt', 'domain']
published_list << ['https://hblock.molinero.dev/hosts_domains.txt', 'dns/hblock.txt', 'domain']
published_list << ['https://o0.pages.dev/Pro/domains.wildcards', 'dns/1hosts.txt', 'domain']
published_list << ['https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt', 'dns/developerdan.txt', 'host']
published_list.each do |url, filename, format|
  begin
    response = HTTParty.get(url)
    File.write(filename, response.body) if response.code == 200
  rescue => error
  end
  adblock_format(filename) if format == 'abp'
  domain_format(filename) if format == 'domain'
  host_format(filename) if format == 'host'
end


blocklists = []
blocklists << ['https://easylist.to/easylist/easyprivacy.txt', 'easylist/easyprivacy.txt']
# uBlock compatible
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/2.txt', 'ublock/adguard_base.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/2_optimized.txt', 'ublock/adguard_base_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/3.txt', 'ublock/adguard_tracking_protection.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/3_optimized.txt', 'ublock/adguard_tracking_protection_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/4.txt', 'ublock/adguard_social.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/4_optimized.txt', 'ublock/adguard_social_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/11.txt', 'ublock/adguard_mobile.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/11_optimized.txt', 'ublock/adguard_mobile_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/14.txt', 'ublock/adguard_annoyances.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/14_optimized.txt', 'ublock/adguard_annoyances_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/17.txt', 'ublock/adguard_url_tracking.txt']
blocklists << ['https://filters.adtidy.org/extension/ublock/filters/17_optimized.txt', 'ublock/adguard_url_tracking_optimized.txt']
# AdGuard compatible
blocklists << ['https://filters.adtidy.org/mac_v2/filters/2.txt', 'adguard/adguard_base.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/2_optimized.txt', 'adguard/adguard_base_optimized.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/3.txt', 'adguard/adguard_tracking_protection.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/3_optimized.txt', 'adguard/adguard_tracking_protection_optimized.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/4.txt', 'adguard/adguard_social.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/4_optimized.txt', 'adguard/adguard_social_optimized.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/11.txt', 'adguard/adguard_mobile.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/11_optimized.txt', 'adguard/adguard_mobile_optimized.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/14.txt', 'adguard/adguard_annoyances.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/14_optimized.txt', 'adguard/adguard_annoyances_optimized.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/17.txt', 'adguard/adguard_url_tracking.txt']
blocklists << ['https://filters.adtidy.org/mac_v2/filters/17_optimized.txt', 'adguard/adguard_url_tracking_optimized.txt']
# AdGuard Safari optimized
blocklists << ['https://filters.adtidy.org/extension/safari/filters/2.txt', 'safari/adguard_base.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/2_optimized.txt', 'safari/adguard_base_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/3.txt', 'safari/adguard_tracking_protection.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/3_optimized.txt', 'safari/adguard_tracking_protection_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/4.txt', 'safari/adguard_social.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/4_optimized.txt', 'safari/adguard_social_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/11.txt', 'safari/adguard_mobile.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/11_optimized.txt', 'safari/adguard_mobile_optimized.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/14.txt', 'safari/adguard_annoyances.txt']
blocklists << ['https://filters.adtidy.org/extension/safari/filters/14_optimized.txt', 'safari/adguard_annoyances_optimized.txt']
# AdGuard iOS optimized
blocklists << ['https://filters.adtidy.org/ios/filters/2.txt', 'ios/adguard_base.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/2_optimized.txt', 'ios/adguard_base_optimized.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/3.txt', 'ios/adguard_tracking_protection.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/3_optimized.txt', 'ios/adguard_tracking_protection_optimized.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/4.txt', 'ios/adguard_social.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/4_optimized.txt', 'ios/adguard_social_optimized.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/11.txt', 'ios/adguard_mobile.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/11_optimized.txt', 'ios/adguard_mobile_optimized.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/14.txt', 'ios/adguard_annoyances.txt']
blocklists << ['https://filters.adtidy.org/ios/filters/14_optimized.txt', 'ios/adguard_annoyances_optimized.txt']

blocklists.each do |url, filename|
  original_rules_count = 0
  selected_rules = ["! Title: #{filename.split('.')[0].split('/')[1].split('_').collect{|x| x.capitalize}.join(" ")}"]
  selected_rules << ["! TimeUpdated: #{DateTime.now.new_offset(0).to_s}"]
  selected_rules << ['! Expires: 6 hours (update frequency)']
  selected_rules << ['! Homepage: https://github.com/specter78/adblock']
  $tld_optimization.each{ |x| $dns_blocked[x] = true } if /.*(?:annoyances|social).*/.match(filename) # filter list optimization
  
  response = HTTParty.get(url)
  next if response.code != 200
  response.body.each_line do |line|
    original_rules_count += 1
    line = line.strip
    if line.start_with?('!')
    elsif line == ''
    elsif line.start_with?('/^') || line.start_with?('@@/^')
      selected_rules << line
    elsif /^e?mail\..*\$image$/.match(line) # filter list optimization
      discarded_rules << line
    elsif already_blocked?(line)
      discarded_rules << line
    else
      line = additional_domains(line)
      selected_rules << line if line != ""
    end
  end

  $tld_optimization.each{ |x| $dns_blocked[x] = false } if /.*(?:annoyances|social).*/.match(filename)
  File.write(filename, selected_rules.join("\n")) if (File.read(filename).split("\n")[4..-1] != selected_rules[4..-1])
  readme << "| #{filename.split('.')[0]} | #{original_rules_count} | #{selected_rules.count} |"
end

File.write("README.md", readme.join("\n"))
