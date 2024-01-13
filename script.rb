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

def already_blocked?(domain, line, filename)
  if capture = /^(?:@@)?(?:\|\|?)?(?:https?)?(?:\:\/\/)?([^#^\^^$^%]+)(.*)/.match(domain)
    return true unless capture[1].ascii_only?
    return false if capture[1].index('.') && capture[1].index('/') && (capture[1].index('/') < capture[1].index('.'))
    domain = capture[1].split('/')[0]
    return false if domain[-1] == '.'
    return false if domain[0] == '~'
    
    if /optimized/.match(filename) # filter list optimization      
      return true if /(?:facebook\.com|facebook\.net|onion)$/.match(domain) # selected domains in all files
      return true if /^(.*\.)?yandex\./.match(domain) && line.include?('#') # yandex in all files
      return true if /^(.*\.)?google\./.match(domain) && (not /\.(?:com\*?|in|\*)$/.match(domain)) # !com and !in google in all files
      return true if /^amazon\./.match(domain) && (not /\.(?:com\*?|in|\*)$/.match(domain)) # !com and !in amazon in all files
      # return true if /(?:#@?%#|#@?\?#|#@?\$\?#)/.match(line) && /\.(?:pl|jp|ru|de|fr|es)$/.match(domain) # advanced/extended rules for selected tlds
      return true if /(?:##|#@?%#|#@?\?#|#@?\$\?#)/.match(line) && /\.(?:de|jp|pl)$/.match(domain) # rules for selected tlds
      return true if /^e?mail\..*\$image$/.match(line)
      if /(?:annoyances|social)/.match(filename)
        return true if (line.start_with?('||') || line.include?('#') || line.include?('domain=')) && domain.include?('.') && (not /\.(?:com|in|io|org|to|tv|\*)$/.match(domain)) # tlds in annoyances and social
      end
    end
    
    while domain.index('.') != nil
      return true if $dns_blocked[domain] && !domain.include?('*')
      domain = domain[(domain.index('.')+1)..-1]
    end
    return true if $dns_blocked[domain] # tld
  end
  return false
end

def optimize_rule(line, filename)

  # $domain ["=" pattern]
  if line.start_with?('[$domain=')
    return "" if already_blocked?(line[9..-1].split(']')[0].split(',')[0], nil, nil)
  end
  
  if capture = /#%#\/\/scriptlet\(['"]prevent-(?:fetch|xhr)['"], ['"]([^'^"^|^\)]+)['"]\)$/.match(line)
    return "" if already_blocked?(capture[1], nil, nil)
  end
  if capture = /##\+js\(no-(?:fetch|xhr)-if, ([^|^\)]+)\)$/.match(line)
    return "" if already_blocked?(capture[1], nil, nil)
  end
  
  # $path ["=" pattern]
  path = false
  if line.start_with?('[$path')
    path = line[0..line.index(']')]
    line = line[line.index(']')+1..-1]
  end

  # beginning domains
  if capture = /^((?:@@)?(?:\|\|)?)([^#^\^^$^%]+)(.*)/.match(line)
    domains = capture[2].split(',').delete_if { |x| already_blocked?(x, line, filename) }
    return "" if domains == []
    line = capture[1] + domains.join(',') + capture[3]

    plus_domain_before, plus_domain_after = false, false
    capture[2].split(',').each { |x| plus_domain_before = true if x[0] != '~' }
    domains.each { |x| plus_domain_after = true if x[0] != '~' }
    return "" if (plus_domain_before == true && plus_domain_after == false)
  end
  
  # ending domains
  if capture = /^(.*)((?:\$|,)domain=)([^#^\^^$^%]+)(.*)/.match(line)
    domains = capture[3].split('|').delete_if { |x| already_blocked?(x, line, filename) }
    return "" if domains == []
    line = capture[1] + capture[2] + domains.join('|') + capture[4]

    plus_domain_before, plus_domain_after = false, false
    capture[3].split('|').each { |x| plus_domain_before = true if x[0] != '~' }
    domains.each { |x| plus_domain_after = true if x[0] != '~' }
    return "" if (plus_domain_before == true && plus_domain_after == false)
  end
  path ? (return path + line) : (return line)
end


$dns_blocked = Hash.new(false)
readme = []
readme << "The script removes rules that are blocked by DNS based blocking.\n\n"
readme << "| File | Original | Modified |"
readme << "|:----:|:-----:|:-----:|"


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
  selected_rules << ['! Expires: 12 hours (update frequency)']
  selected_rules << ['! Homepage: https://github.com/specter78/adblock']
  
  response = HTTParty.get(url)
  next if response.code != 200
  response.body.each_line do |line|
    original_rules_count += 1
    line = line.strip
    if line.start_with?('!')
    elsif line == ''
    elsif line.start_with?('/^') || line.start_with?('@@/^')
      selected_rules << line
    else
      line = optimize_rule(line, filename)
      selected_rules << line if line != ""
    end
  end

  File.write(filename, selected_rules.join("\n")) if (File.read(filename).split("\n")[4..-1] != selected_rules[4..-1])
  readme << "| #{filename.split('.')[0]} | #{original_rules_count} | #{selected_rules.count} |"
end

File.write("README.md", readme.join("\n"))
