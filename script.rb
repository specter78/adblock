adblock = []
discarded = []

3.times do |n|
  file_number = n + 1
  File.open("#{file_number}.txt", "r") do |f|
    f.each_line do |line|
      line = line.strip
      if line.start_with?('!')
      elsif (line.count('/') == 0) && (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party'))
        discarded << line
      else
        adblock << line
      end
    end
  end
end

adblock = adblock.uniq
discarded = discarded.uniq

File.write("adblock.txt", adblock.join("\n"))
File.write("discarded.txt", discarded.join("\n"))
