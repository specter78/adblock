require 'httparty'

def already_blocked?(url)
  if capture = /^(?:@@)?(?:\|\|)?([^#^\^^$^%]+)(.*)/.match(url)
    return if capture[1].include?(',')
    return unless capture[1].ascii_only?
    capture[1].split('/')[0].include?('.') ? (domain = capture[1].split('/')[0].split(':')[0]) : (domain = capture[1])
    return if domain.include?('*')
    return if domain.include?('~')
    return if domain[-1] == '.'
    return if domain[-1] == '-'
    return if domain[-1] == '_'
    puts domain
    $domain_rules[domain] += 1
    $tld_rules[domain.split('.').last] += 1
    # $domain_rules[domain.split('.')[-2..-1].join('.')] += 1
    # while domain.index('.') != nil
    #   return true if $dns_blocked[domain]
    #   domain = domain[(domain.index('.')+1)..-1]
    # end
  end
end

def additional_domains(line)
  # beginning domains
  if capture = /^((?:@@)?(?:\|\|)?)([^#^\^^$^%]+)(.*)/.match(line)
    capture[2].split(',').each {|x| already_blocked?(x)}
  end
  
  # ending domains
  if capture = /^(.*)(\$domain=)([^#^\^^$^%]+)(.*)/.match(line)
    capture[3].split("|").each {|x| already_blocked?(x)}
  end
end

$domain_rules = Hash.new(0)
$tld_rules = Hash.new(0)
blocklists = []
blocklists << ['https://raw.githubusercontent.com/specter78/adblock/main/adguard/adguard_social.txt']
blocklists << ['https://raw.githubusercontent.com/specter78/adblock/main/adguard/adguard_annoyances.txt']
# blocklists << ['https://raw.githubusercontent.com/specter78/adblock/main/adguard/adguard_base.txt']
# blocklists << ['https://raw.githubusercontent.com/specter78/adblock/main/adguard/adguard_mobile.txt']
# blocklists << ['https://raw.githubusercontent.com/specter78/adblock/main/adguard/adguard_tracking_protection.txt']
# blocklists << ['https://raw.githubusercontent.com/specter78/adblock/main/adguard/adguard_url_tracking.txt']

blocklists.each do |list|
  response = HTTParty.get(list[0])
  next if response.code != 200
  response.body.each_line do |line|
    line = line.strip
    next if line.start_with?('!')
    next if line == ''
    next if line.start_with?('/^') || line.start_with?('@@/^')
    additional_domains(line)
  end
end

readme = []
readme << "Domain Counter\n\n"
readme << "| Domain | Rules |"
readme << "|:----:|:-----:|"
$domain_rules.delete_if {|k,v| v <= 50 }.to_a.sort_by{ |x| x[1] }.reverse.each{ |x| readme << "| #{x[0]} | #{x[1]} |" }
readme << "\n\nTLD Counter\n\n"
readme << "| TLD | Rules |"
readme << "|:----:|:-----:|"
$tld_rules.delete_if {|k,v| v <= 50 }.to_a.sort_by{ |x| x[1] }.reverse.each{ |x| readme << "| #{x[0]} | #{x[1]} |" }
File.write("README.md", readme.join("\n"))
