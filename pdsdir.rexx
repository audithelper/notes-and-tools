/* rexx - list members of a PDS/PDSE by reading its directory */
parse arg dsn .
if dsn = '' then dsn = 'SYS1.PARMLIB'
dsn = strip(dsn, 'B', "'")

/* Allocate the PDS as a sequential file of 256-byte blocks */
rc = bpxwdyn("alloc fi(pdsdir) da('"dsn"') shr msg(2)",
             "recfm(f) lrecl(256) blksize(256) dsorg(ps)")
if rc <> 0 then do
  say 'ALLOC failed for' dsn 'rc='rc
  exit 8
end

address mvs "execio * diskr pdsdir (stem blk. finis"
if rc <> 0 then do
  say 'EXECIO failed rc='rc
  call bpxwdyn 'free fi(pdsdir)'
  exit 8
end

count = 0
do i = 1 to blk.0
  used = c2d(substr(blk.i, 1, 2))      /* bytes used, incl. this field */
  p = 3
  do while p < used
    name = substr(blk.i, p, 8)
    if name = 'FFFFFFFFFFFFFFFF'x then signal done   /* end of directory */
    info = c2d(substr(blk.i, p + 11, 1))
    ulen = (info // 32) * 2           /* low 5 bits = user data halfwords */
    say strip(name)
    count = count + 1
    p = p + 12 + ulen                  /* 8 name + 3 TTR + 1 flag + userdata */
  end
end

done:
say count 'member(s) in' dsn
call bpxwdyn 'free fi(pdsdir)'
exit 0
