def trim_string(str)
  if str.nil? || str.empty?
    str
  else
    str.strip
  end
end