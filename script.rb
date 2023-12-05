require 'httparty'

blocklists = ['adguard_ads.txt', 'easylist.txt', 'adguard_privacy.txt', 'easyprivacy.txt', 'adguard_mobile.txt']
discarded_rules = []
total_rules = 0
$dns_blocked = []

readme = []
readme << "The script removes rules that can be blocked by DNS based ad-blocking.\n\n"
readme << "| File | Rules |"
readme << "|:----:|:-----:|"

HTTParty.get('https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt').body.each_line do |url|
  url = url.strip
  next if url.start_with?('!')
  next if url.start_with?('@@')
  url = url[2..-1] if url.start_with?('||')
  url = url[0..-2] if url.end_with?('^')
  $dns_blocked << url
end

def already_blocked?(url)
  puts url
  url = url[2..-1] if url.start_with?('||')
  url = url.split('^')[0].split('/')[0]
  return $dns_blocked.include?(url)
end


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
