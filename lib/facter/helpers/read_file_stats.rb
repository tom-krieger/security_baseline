# frozen_string_literal: true

# get uid, gid, and perms of a file

def read_file_stats(filename)
  uid = File.stat(filename).uid
  gid = File.stat(filename).gid
  mode = File.stat(filename).mode & 0o7777
  ret = {
    'uid' => uid,
    'gid' => gid,
    'mode' => mode,
  }

  ret
end
