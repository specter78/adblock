ads = []
privacy = []
discarded = []

3.times do |n|
  file_number = n + 1
  File.open("#{file_number}.txt", "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('! Checksum:')
      elsif (line.count('/') == 0) && (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party'))
        discarded << line
      else
        (file_number <= 2) ? (ads << line) : (privacy << line)
      end
    end
  end
end

# adguard = adguard.uniq
# easylist = easylist.uniq
# discarded = discarded.uniq

File.write("ads.txt", ads.join("\n"))
File.write("privacy.txt", privacy.join("\n"))
File.write("discarded.txt", discarded.join("\n"))
