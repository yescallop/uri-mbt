let table_len : Int = 128 + 3

let index_pct_encoded : Int = 128

let index_ucschar : Int = 128 + 1

let index_iprivate : Int = 128 + 2

fn is_ucschar(x : Int) -> Bool {
  (x >= 0xa0 && x <= 0xd7ff) ||
  (x >= 0xf900 && x <= 0xfdcf) ||
  (x >= 0xfdf0 && x <= 0xffef) ||
  (x >= 0x10000 && x <= 0xdffff && (x & 0xffff) <= 0xfffd) ||
  (x >= 0xe1000 && x <= 0xefffd)
}

fn is_iprivate(x : Int) -> Bool {
  (x >= 0xe000 && x <= 0xf8ff) || (x >= 0xf0000 && (x & 0xffff) <= 0xfffd)
}

pub struct T {
  table : FixedArray[Bool]
}

pub fn new(bytes : Bytes) -> T {
  let table = FixedArray::make(table_len, false)
  for byte in bytes {
    if byte.to_int() >= 128 || byte == b'%' {
      abort("cannot allow non-ASCII byte or %")
    }
    table[byte.to_int()] = true
  }
  { table, }
}

pub fn or(self : T, other : T) -> T {
  let table = self.table.copy()
  for i, b in other.table {
    table[i] = table[i] || b
  }
  { table, }
}

pub fn or_pct_encoded(self : T) -> T {
  let table = self.table.copy()
  table[index_pct_encoded] = true
  { table, }
}

pub fn or_ucschar(self : T) -> T {
  let table = self.table.copy()
  table[index_ucschar] = true
  { table, }
}

pub fn or_iprivate(self : T) -> T {
  let table = self.table.copy()
  table[index_iprivate] = true
  { table, }
}

pub fn sub(self : T, other : T) -> T {
  let table = self.table.copy()
  for i, b in other.table {
    table[i] = table[i] && not(b)
  }
  { table, }
}

pub fn is_subset(self : T, other : T) -> Bool {
  for i, b in other.table {
    if self.table[i] && not(b) {
      return false
    }
  }
  true
}

pub fn allows(self : T, ch : Char) -> Bool {
  let x = ch.to_int()
  if x < 128 {
    self.table[x]
  } else {
    (self.table[index_ucschar] && is_ucschar(x)) ||
    (self.table[index_iprivate] && is_iprivate(x))
  }
}

pub fn allows_pct_encoded(self : T) -> Bool {
  self.table[index_pct_encoded]
}

pub let alpha : T = new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

pub let digit : T = new(b"0123456789")

pub let hexdig : T = digit.or(new(b"ABCDEFabcdef"))

pub let scheme : T = alpha.or(digit).or(new(b"+-."))

pub let userinfo : T = unreserved.or(sub_delims).or(new(b":")).or_pct_encoded()

pub let ipv_future : T = unreserved.or(sub_delims).or(new(b":"))

pub let reg_name : T = unreserved.or(sub_delims).or_pct_encoded()

pub let path : T = pchar.or(new(b"/"))

pub let segment_nz_nc : T = unreserved
  .or(sub_delims)
  .or(new(b"@"))
  .or_pct_encoded()

pub let pchar : T = unreserved.or(sub_delims).or(new(b":@")).or_pct_encoded()

pub let query : T = pchar.or(new(b"/?"))

pub let fragment : T = query

pub let unreserved : T = alpha.or(digit).or(new(b"-._~"))

pub let reserved : T = gen_delims.or(sub_delims)

pub let gen_delims : T = new(b":/?#[]@")

pub let sub_delims : T = new(b"!$&'()*+,;=")

pub let iuserinfo : T = userinfo.or_ucschar()

pub let ireg_name : T = reg_name.or_ucschar()

pub let ipath : T = path.or_ucschar()

pub let isegment_nz_nc : T = segment_nz_nc.or_ucschar()

pub let iquery : T = query.or_ucschar().or_iprivate()

pub let ifragment : T = fragment.or_ucschar()
