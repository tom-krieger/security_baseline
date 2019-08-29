# frozen_string_literal: true

# duplicate_user.rb
# Ensures there are no duplicate UIDs in /etc/passwd
Facter.add('duplicate_user') do
  confine :kernel => 'Linux'
  setcode do
    users = ''
    if File.exists?('/etc/passwd')
      userdata = {}
      lines = File.open('/etc/passwd').readlines()
      lines.each do |line|
        next if line =~/^#/
        data = line.split(/:/)
        user = data[0]
        uid = data[2]
        if userdata.key?(user) then
          userdata[uid][:cnt] = userdata[user]['cnt'] + 1
          userdata[uid][:uid] = "#{userdata[user][:uid]};#{uid}"
        else
          userdata[user] = {:cnt => 1, :uid => uid}
        end
      end 
      userdata.each do |user, value|
        if value[:cnt] > 1 then
            users = "Duplicate user #{user} Uids: #{value[:uid]}"
        end
      end

    end
    
    users
  end
end
