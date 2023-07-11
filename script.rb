adblock = []
discarded = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    if (line.match(/^\|\|.*\^$/))
      discarded << line
    else
      adblock << line
  end
end

File.write("adblock.txt", discarded.join("\n"))
