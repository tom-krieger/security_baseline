# read_duplicate_groups.rb
# get duplicate groups by gid and/or group name
# mykey = gid : gets duplicate gids
# mykey = group : get duplicate group names

def read_duplicate_groups(mykey)
  groups = ''
  if File.exist?('/etc/group')
    groupdata = {}
    lines = File.open('/etc/group').readlines
    lines.each do |line|
      next if line =~ %r{^#}
      data = line.split(%r{:})
      group = data[0]
      gid = data[2]
      if mykey == 'gid'
        if groupdata.key?(gid)
          groupdata[gid][:cnt] = groupdata[gid]['cnt'] + 1
          groupdata[gid][:group] = "#{groupdata[gid][:group]};#{group}"
        else
          groupdata[gid] = { cnt: 1, group: group }
        end
      elsif mykey == 'group'
        if groupdata.key?(group)
          groupdata[gid][:cnt] = groupdata[group]['cnt'] + 1
          groupdata[gid][:gid] = "#{groupdata[group][:gid]};#{gid}"
        else
          groupdata[group] = { cnt: 1, gid: gid }
        end
      end
    end
    groupdata.each do |gid, value|
      if value[:cnt] > 1
        if mykey == 'gid'
          groups = "Duplicate gid #{gid} groups: #{value[:group]}"
        elsif mykey == 'group'
          groups = "Duplicate group #{group} Gids: #{value[:gid]}"
        end
      end
    end

  end

  groups
end
