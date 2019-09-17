# frozen_string_literal: true

# duplicate_uid.rb
# Ensures there are no duplicate UIDs in /etc/passwd
Facter.add('duplicate_uid') do
  confine kernel: 'Linux'
  setcode do
    users = ''
    if File.exist?('/etc/passwd')
      userdata = {}
      lines = File.open('/etc/passwd').readlines
      lines.each do |line|
        next if line =~ %r{^#}
        data = line.split(%r{:})
        user = data[0]
        uid = data[2]
        if userdata.key?(uid)
          userdata[uid][:cnt] = userdata[uid]['cnt'] + 1
          userdata[uid][:user] = "#{userdata[uid][:user]};#{user}"
        else
          userdata[uid] = { cnt: 1, user: user }
        end
      end

      userdata.each do |uid, value|
        if value[:cnt] > 1
          users = "Duplicate uid #{uid} Users: #{value[:user]}"
        end
      end

    end

    users
  end
end
