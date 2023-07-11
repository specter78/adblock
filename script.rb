adblock = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    line = line.strip
    if line.start_with?('!')
    elsif line.start_with?('||') && line.end_with?('.com^')
    elsif line.start_with?('||') && line.end_with?('.in^')
    else
      adblock << line
    end
  end
end

adblock.uniq!

File.write("adblock.txt", adblock.join("\n"))
