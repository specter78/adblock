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

final = adblock
final << ["---", "---", "---"]
final << discarded

File.write("adblock.txt", final.join("\n"))
