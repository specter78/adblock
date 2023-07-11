adblock = []
discarded = []

File.open("2.txt", "r") do |f|
  f.each_line do |line|
    if line == ""
    elsif (/^\|\|.*\.com^$/.match(line)) != nil
      discarded << line
    else
      adblock << line
    end
  end
end

final_array = []
final_array << adblock
final_array << ["-----", "-----", "-----", "-----", "-----"]
final_array << discarded

File.write("adblock.txt", discarded.join("\n"))
