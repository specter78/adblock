selected_rules = []
discarded_rules = []
blocklists = ['adguard_ads.txt', 'easylist.txt', 'adguard_privacy.txt', 'easyprivacy.txt']

blocklists.each do |blocklist|
  File.open(blocklist, "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('! Checksum:')
      elsif (line.count('/') == 0) && (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party'))
        discarded_rules << line
      else
        selected_rules << line
      end
    end
  end
  File.write(blocklist, selected_rules.join("\n"))
  selected_rules = []
  discarded_rules = []
end
