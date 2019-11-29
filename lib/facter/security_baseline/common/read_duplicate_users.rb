# read_duplicate_users.rb
# get duplicate users by uid and/os username
# mykey = uid : gets duplicate uids
# mykey = user : gets duplicate usernames

def read_duplicate_users(mykey)
  users = ''
  if File.exist?('/etc/passwd')
    userdata = {}
    lines = File.open('/etc/passwd').readlines
    lines.each do |line|
      next if line =~ %r{^#}
      data = line.split(%r{:})
      user = data[0]
      uid = data[2]
      if mykey == 'uid'
        if userdata.key?(uid)
          userdata[uid][:cnt] = userdata[uid]['cnt'] + 1
          userdata[uid][:user] = "#{userdata[uid][:user]};#{user}"
        else
          userdata[uid] = { cnt: 1, user: user }
        end
      elsif mykey == 'user'
        if userdata.key?(user)
          userdata[uid][:cnt] = userdata[user]['cnt'] + 1
          userdata[uid][:uid] = "#{userdata[user][:uid]};#{uid}"
        else
          userdata[user] = { cnt: 1, uid: uid }
        end
      end
    end

    userdata.each do |uid, value|
      if value[:cnt] > 1
        if mykey == 'uid'
          users = "Duplicate uid #{uid} Users: #{value[:user]}"
        elsif mykey == 'user'
          users = "Duplicate user #{user} Uids: #{value[:uid]}"
        end
      end
    end

  end

  users
end
