blocklists = ['adguard_ads.txt', 'easylist.txt', 'adguard_privacy.txt', 'easyprivacy.txt', 'adguard_mobile.txt']

blocklists.each do |blocklist|
  selected_rules = []
  discarded_rules = []
  skip_comments = false
  File.open(blocklist, "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('! Checksum:')
        # do nothing
      elsif line.start_with?('!')
        (skip_comments = true) if line.start_with?('!--')
        (selected_rules << line) unless skip_comments
      elsif (line.count('/') == 0) && (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party'))
        discarded_rules << line
      else
        selected_rules << line
      end
    end
  end
  File.write(blocklist, selected_rules.join("\n"))
end
