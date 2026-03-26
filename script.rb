require 'date'
require 'httparty'

def adblock_format(blocklist)
  blocklist.each_line do |line|
    line = line.strip
    if capture = /^(?:@@)?(?:\|\|?)?([a-zA-Z0-9\.\-\_]+)\^?\|?$/.match(line)
      next if /[^a-zA-Z0-9]/.match?(capture[1][0]) || /[^a-zA-Z0-9]/.match?(capture[1][-1])
      line.start_with?('@@') ? $allowed[capture[1]] = true : $blocked[capture[1]] = true
    end
  end
end

def domain_format(blocklist)
  blocklist.each_line do |line|
    line = line.split('#').first.strip
    if capture = /^(?:\*\.)?([a-zA-Z0-9\.\-\_]+)$/.match(line)
      $blocked[capture[1]] = true
    end
  end
end

def host_format(blocklist)
  blocklist.each_line do |line|
    line = line.split('#').first.strip
    if capture = /^(?:0\.0\.0\.0\s)([a-zA-Z0-9\.\-\_]+)$/.match(line)
      $blocked[capture[1]] = true
    end
  end
end


def already_blocked?(domain, line, platform, filename)
  if capture = /^(?:@@)?(?:\|\|?)?(?:https?)?(?:\:\/\/)?([^#^\^^$^%]+)(.*)/.match(domain)
    domain = capture[1].split('/').first
    return false if domain.nil? || domain[0] == '~' || !domain.include?('.')
    
    # filter list optimization      
    return true if /^(.*\.)?(?:onion)$/.match?(domain) # selected domains in all files
    return true if /#.?.?#/.match?(line) && /^(.*\.)?yandex\./.match?(domain)
    return true if /#.?.?#/.match?(line) && /\.(?:de|jp|pl|ru)$/.match?(domain) # selected tlds in all files
    return true if /^e?mail\..*\$image$/.match?(line)
    if /(?:annoyances|social)/.match?(filename)
      return true if /#.?.?#/.match?(line) && (not /\.(?:com|in|io|org|to|tv|\*)$/.match?(domain)) # tlds in annoyances and social
    end
    
    while domain.index('.') != nil
      return false if $allowed[domain]
      return true if $blocked[domain]
      domain = domain[(domain.index('.')+1)..-1]
    end
    return true if $blocked[domain] # tld
  end
  return false
end


def optimize_rule(line, platform, filename)
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

$allowed = Hash.new(false)
response = HTTParty.get('https://raw.githubusercontent.com/nextdns/click-tracking-domains/main/domains')
raise "Failed to download 'affiliate_tracking_domains' - Status: #{response.code}" unless response.success?
response.body.each_line(chomp: true) do |line|
  if capture = /^([^#]+)/.match(line)
    $allowed[capture[1]] = true
  end
end

# --------------------------

$blocked = Hash.new(false)
blocklists = []
blocklists << ['https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', 'abp']
blocklists << ['https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt', 'domain']
blocklists << ['https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'host']
blocklists << ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt', 'domain']
blocklists << ['https://hblock.molinero.dev/hosts_domains.txt', 'domain']
blocklists << ['https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.wildcards', 'domain']
blocklists.each do |url, format|
  response = HTTParty.get(url)
  raise "Failed to download #{url} - Status: #{response.code}" unless response.success?
  adblock_format(response.body) if format == 'abp'
  domain_format(response.body) if format == 'domain'
  host_format(response.body) if format == 'host'
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

filters.each do |filter, filename|
  platforms.each do |platform|

    response = HTTParty.get("https://filters.adtidy.org/#{platform}/filters/#{filter}.txt")
    next if response.code != 200

    folder = platform.gsub('extension/', '').gsub('_v2', '')
    File.write("#{folder}/#{filename}.txt", response.body)

    original_rules_count = response.body.split("\n").count{ |line| (line[0] != '!') && (line != '') }
    selected_rules = ["! Title: #{filename.split('_').collect{|x| x.capitalize}.join(" ")} Optimized"]
    selected_rules << ["! TimeUpdated: #{DateTime.now.new_offset(0).to_s}"]
    selected_rules << ['! Expires: 12 hours (update frequency)']
    selected_rules << ['! Homepage: https://github.com/specter78/adblock']

    response.body.each_line(chomp: true) do |line|
      next if line.empty? || line[0] == '!'
      if not (line.start_with?('/^') || line.start_with?('@@/^'))
        line = optimize_rule(line, platform, filename)
      end
      selected_rules << line if line != ""
    end

    File.write("#{folder}/#{filename}_optimized.txt", selected_rules.join("\n")) if (File.read("#{folder}/#{filename}_optimized.txt").split("\n")[4..-1] != selected_rules[4..-1])
    readme << "| #{folder}/#{filename}_optimized | #{original_rules_count} | #{selected_rules.count - 4} |"
  end

  merged_rules = File.read("mac/#{filename}_optimized.txt").split("\n") + File.read("ios/#{filename}_optimized.txt").split("\n")[4..-1] + File.read("safari/#{filename}_optimized.txt").split("\n")[4..-1]
  File.write("apple/#{filename}_optimized.txt", merged_rules.uniq.join("\n"))

end

readme[3..-1] = readme[3..-1].sort
File.write("README.md", readme.join("\n"))
