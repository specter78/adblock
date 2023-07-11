adguard = []
easylist = []
discarded = []
merged = []

5.times do |n|
  file_number = n + 1
  File.open("#{file_number}.txt", "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('!')
      elsif (line.count('/') == 0) && (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party'))
        discarded << line
      else
        (file_number <= 3) ? (adguard << line) : (easylist << line)
      end
    end
  end
end

adguard = adguard.uniq
easylist = easylist.uniq
discarded = discarded.uniq

merged = adguard + easylist
merged = merged.uniq

puts "#{adguard.length} + #{easylist.length} = #{merged.length}"

File.write("adguard.txt", adguard.join("\n"))
File.write("easylist.txt", easylist.join("\n"))
File.write("discarded.txt", discarded.join("\n"))
File.write("merged.txt", merged.join("\n"))
