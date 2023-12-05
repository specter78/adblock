blocklists = ['adguard_ads.txt', 'easylist.txt', 'adguard_privacy.txt', 'easyprivacy.txt', 'adguard_mobile.txt']
discarded_rules = []
total_rules = 0
readme = []
readme << "The script removes rules that can be blocked by DNS based ad-blocking.\n\n"
readme << "| File | Rules |"
readme << "|:----:|:-----:|"

blocklists.each do |blocklist|
  selected_rules = []
  skip_comments = false
  File.open(blocklist, "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('! Checksum:')
        # do nothing
      elsif line.start_with?('!')
        (skip_comments = true) if line.start_with?('!--')
        (selected_rules << line) unless skip_comments
      elsif line[0..-2].count('/') > 0 # i.e. '/' does not exist ONLY at the end
        selected_rules << line
      elsif (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party') || line.end_with?('^$all') || line.end_with?('^$popup'))
        discarded_rules << line
      elsif (line.start_with?('||')) && /^[a-zA-Z0-9_.]*[a-zA-Z0-9_]$/.match?(line[2..-1])
        discarded_rules << line
      elsif line.include?('$network')
        discarded_rules << line
      elsif line.start_with?('||graph.facebook.com')
        discarded_rules << line
      else
        selected_rules << line
      end
    end
  end
  File.write(blocklist, selected_rules.join("\n"))
  readme << "| #{blocklist} | #{selected_rules.count} |"
  total_rules += selected_rules.count
end

readme << "| Total | #{total_rules.count} |"
File.write("discarded.txt", discarded_rules.join("\n"))
File.write("README.md", readme.join("\n"))
