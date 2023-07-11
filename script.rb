adblock = []
discarded = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    if line.start_with?('||') && line.end_with?('.com^')
        discarded << line
    else
      adblock << line
    end
  end
end

File.write("adblock.txt", discarded.join("\n"))
