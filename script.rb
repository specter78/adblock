adblock = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    line = line.strip
    if line.start_with?('!')
    if line.start_with?('||') && line.end_with?('.com^')
    if line.start_with?('||') && line.end_with?('.in^')
    else
      adblock << line
    end
  end
end

File.write("adblock.txt", adblock.join("\n"))
