adblock = []
dicarded = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    line = line.strip
    if line.start_with?('!')
    # elsif line.start_with?('||') && line.end_with?('.com^')
    # elsif line.start_with?('||') && line.end_with?('.in^')
    elsif (line.count('/') != 0) && (line.start_with?('||')) && (line.end_with?('^') || line.end_with?('^$third-party'))
      discarded << line
    else
      adblock << line
    end
  end
end

File.write("adblock.txt", discarded.join("\n"))
