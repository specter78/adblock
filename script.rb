adblock = []
discarded = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    if line == ""
    elsif (/^\|\|.*\^$/.match(line)) !- nil
      discarded << line
    else
      adblock << line
    end
  end
end

final_array = []
# final_array << adblock
# final_array << ["-----", "-----", "-----", "-----", "-----"]
final_array << discarded

File.write("adblock.txt", final_array.join("\n"))
