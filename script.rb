require 'httparty'

def already_blocked?(line)
  if capture = /^(?:@@)?(?:\|\|?)?(?:https?)?(?:\:\/\/)?([^#^\^^$^%]+)(.*)/.match(line)
    return if capture[1].include?(',')
    return unless capture[1].ascii_only?
    # return if capture[1][-1] == '.'
    return if capture[1][0] == '~'
    return if capture[1].index('.') && capture[1].index('/') && (capture[1].index('/') < capture[1].index('.'))
    domain = capture[1].split('/')[0]
    if domain.include?('.')
      # domain = capture[1].split('.')[-2..-1].join('.')
      domain = domain.split('.')[-2]
      tld = domain.split('.')[-1]
      $domain_rules[domain] += 1
      $tld_rules[tld] += 1
    else
      $tld_rules[domain] += 1
    end
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
blocklists << 'https://raw.githubusercontent.com/specter78/adblock/main/ublock/adguard_annoyances_optimized.txt'
# blocklists << 'https://raw.githubusercontent.com/specter78/adblock/main/ublock/adguard_base_optimized.txt'
# blocklists << 'https://raw.githubusercontent.com/specter78/adblock/main/ublock/adguard_mobile_optimized.txt'
blocklists << 'https://raw.githubusercontent.com/specter78/adblock/main/ublock/adguard_social_optimized.txt'
# blocklists << 'https://raw.githubusercontent.com/specter78/adblock/main/ublock/adguard_tracking_protection_optimized.txt'
# blocklists << 'https://raw.githubusercontent.com/specter78/adblock/main/ublock/adguard_url_tracking_optimized.txt'

blocklists.each do |list|
  response = HTTParty.get(list)
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
$domain_rules.delete_if {|k,v| v < 10 }.to_a.sort_by{ |x| x[1] }.reverse.each{ |x| readme << "| #{x[0]} | #{x[1]} |" }
readme << "\n\nTLD Counter\n\n"
readme << "| TLD | Rules |"
readme << "|:----:|:-----:|"
$tld_rules.delete_if {|k,v| v < 50 }.to_a.sort_by{ |x| x[1] }.reverse.each{ |x| readme << "| #{x[0]} | #{x[1]} |" }
File.write("README.md", readme.join("\n"))
