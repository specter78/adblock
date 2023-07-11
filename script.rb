adblock = []
discarded = []

File.open("1.txt", "r") do |f|
  f.each_line do |line|
    if line == ""
    elsif line.start_with? "||"
      if line.end_with? ".com^"
        discarded << line
      else
        adblock << line
      end
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
