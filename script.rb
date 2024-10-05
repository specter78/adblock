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

def already_blocked?(domain, line, platform, filename)
  if capture = /^(?:@@)?(?:\|\|?)?(?:https?)?(?:\:\/\/)?([^#^\^^$^%]+)(.*)/.match(domain)
    return true unless capture[1].ascii_only?
    return false if capture[1].index('.') && capture[1].index('/') && (capture[1].index('/') < capture[1].index('.'))
    domain = capture[1].split('/')[0]
    return false if domain[0] == '['
    return false if domain[0] == '/'
    return false if domain[-1] == '.'
    return false if domain[0] == '~'
    
    # filter list optimization      
    return true if /^(.*\.)?(?:facebook\.com|facebook\.net|fb\.com|onion)$/.match(domain) # selected domains in all files
    return true if /^(.*\.)?google\./.match(domain) && (not /\.(?:com\*?|in|\*)$/.match(domain)) # !com and !in google in all files
    return true if /^(?:amazon\.|kayak\.|webike\.|tripadvisor\.|momondo\.|expedia\.|skyscanner\.|yelp\.)/.match(domain) && (not /\.(?:com\*?|in|\*)$/.match(domain)) # !com and !in in all files
    return true if line.count('#') > 1 && /^dizipal\d*\.(?:com|cloud)$/.match(domain) # dizipal in all files
    return true if line.count('#') > 1 && /^(.*\.)?yandex\./.match(domain) # yandex in all files
    return true if line.count('#') > 1 && /\.(?:de|jp|pl|ru)$/.match(domain) # selected tlds in all files
    return true if /^e?mail\..*\$image$/.match(line)
    if /(?:annoyances|social)/.match(filename)
      return true if (line.start_with?('||') || line.include?('#') || line.include?('domain=')) && domain.include?('.') && (not /\.(?:com|in|io|org|to|tv|\*)$/.match(domain)) # tlds in annoyances and social
    end
    
    while domain.index('.') != nil
      return false if $affiliate_tracking_domains[domain]
      return true if $dns_blocked[domain] && !domain.include?('*')
      domain = domain[(domain.index('.')+1)..-1]
    end
    return true if $dns_blocked[domain] # tld
  end
  return false
end

def optimize_rule(line, platform, filename)

  # if capture = /#%#\/\/scriptlet\(['"]prevent-(?:fetch|xhr)['"], ['"]([^'^"^|^\)]+)['"]\)$/.match(line)
  #   return "" if already_blocked?(capture[1], line, platform, filename)
  # end
  # if capture = /##\+js\(no-(?:fetch|xhr)-if, ([^|^\)]+)\)$/.match(line)
  #   return "" if already_blocked?(capture[1], line, platform, filename)
  # end

  # beginning domains
  if capture = /^((?:@@)?(?:\|\|)?)(\[[^\]]*\])?([^#^\^^$^%]+)(.*)/.match(line)
    domains = capture[3].split(',').delete_if { |x| already_blocked?(x, line, platform, filename) }
    return "" if domains == []
    line = capture[1] + capture[2].to_s + domains.join(',') + capture[4]
    return "" if capture[3].split(',').any?{ |e| e[0] != '~'} && domains.none?{ |e| e[0] != '~'}
  end
  
  # ending domains
  if capture = /^(.*)((?:\$|,)domain=)([^#^\^^$^%]+)(.*)/.match(line)
    domains = capture[3].split('|').delete_if { |x| already_blocked?(x, line, platform, filename) }
    return "" if domains == []
    line = capture[1] + capture[2] + domains.join('|') + capture[4]
    return "" if capture[3].split('|').any?{ |e| e[0] != '~'} && domains.none?{ |e| e[0] != '~'}
  end
  
  return line
end

# --------------------------

$dns_blocked = Hash.new(false)
blocklists = []
blocklists << ['https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', 'dns/adguard_dns.txt', 'abp']
blocklists << ['https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt', 'dns/oisd.txt', 'domain']
blocklists << ['https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'dns/stevenblack.txt', 'host']
blocklists << ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt', 'dns/hagezi.txt', 'domain']
blocklists << ['https://hblock.molinero.dev/hosts_domains.txt', 'dns/hblock.txt', 'domain']
blocklists << ['https://o0.pages.dev/Pro/domains.wildcards', 'dns/1hosts.txt', 'domain']
blocklists.each do |url, filename, format|
  begin
    response = HTTParty.get(url)
    File.write(filename, response.body) if response.code == 200
  rescue => error
  end
  adblock_format(filename) if format == 'abp'
  domain_format(filename) if format == 'domain'
  host_format(filename) if format == 'host'
end

# --------------------------

$affiliate_tracking_domains = Hash.new(false)
begin
  response = HTTParty.get('https://raw.githubusercontent.com/nextdns/click-tracking-domains/main/domains')
  File.write('dns/affiliate_tracking_domains.txt', response.body) if response.code == 200
rescue => error
end
File.read('dns/affiliate_tracking_domains.txt').each_line do |line|
  next if line.strip == ''
  if capture = /^([^#]+)/.match(line.strip)
    $affiliate_tracking_domains[capture[1]] = true
  end
end

# --------------------------

readme = []
readme << "The script removes rules that are blocked by DNS based blocking.\n\n"
readme << "| File | Original | Modified |"
readme << "|:----:|:-----:|:-----:|"

platforms = ['extension/ublock', 'mac_v2', 'extension/safari', 'ios']
filters = []
filters  << ['2_optimized', 'adguard_base']
filters  << ['3_optimized', 'adguard_tracking_protection']
filters  << ['4_optimized', 'adguard_social']
filters  << ['11_optimized', 'adguard_mobile']
filters  << ['14_optimized', 'adguard_annoyances']
filters  << ['17_optimized', 'adguard_url_tracking']

# --------------------------

platforms.each do |platform|
  filters.each do |filter, filename|

    response = HTTParty.get("https://filters.adtidy.org/#{platform}/filters/#{filter}.txt")
    next if response.code != 200

    folder = platform.gsub('extension/', '').gsub('_v2', '')
    File.write("#{folder}/#{filename}.txt", response.body)

    original_rules_count = response.body.split("\n").count{ |line| (line[0] != '!') && (line.strip != '') }
    selected_rules = ["! Title: #{filename.split('_').collect{|x| x.capitalize}.join(" ")} Optimized"]
    selected_rules << ["! TimeUpdated: #{DateTime.now.new_offset(0).to_s}"]
    selected_rules << ['! Expires: 12 hours (update frequency)']
    selected_rules << ['! Homepage: https://github.com/specter78/adblock']

    response.body.each_line do |line|
      line = line.strip
      if line.start_with?('!')
      elsif line == ''
      elsif line.start_with?('/^') || line.start_with?('@@/^')
        # selected_rules << line
      else
        line = optimize_rule(line, platform, filename)
        selected_rules << line if line != ""
      end
    end

    File.write("#{folder}/#{filename}_optimized.txt", selected_rules.join("\n")) if (File.read("#{folder}/#{filename}_optimized.txt").split("\n")[4..-1] != selected_rules[4..-1])
    readme << "| #{folder}/#{filename}_optimized | #{original_rules_count} | #{selected_rules.count - 4} |"
  end
end

File.write("README.md", readme.join("\n"))
