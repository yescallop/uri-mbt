pub type! ParseError ParseErrorInner derive(Show)

impl Show for ParseErrorInner with output(self, logger) {
  let msg = match self.kind {
    InvalidOctet => "invalid percent-encoded octet at index "
    UnexpectedChar => "unexpected character at index "
    InvalidIpv6Addr => "invalid IPv6 address at index "
  }
  logger..write_string(msg).write_object(self.index)
}

fn err(index : Int, kind : ParseErrorKind) -> ParseError {
  ParseError({ index, kind })
}

struct ParseErrorInner {
  index : Int
  kind : ParseErrorKind
}

enum ParseErrorKind {
  InvalidOctet
  UnexpectedChar
  InvalidIpv6Addr
}

struct Criteria {
  must_be_ascii : Bool
  must_have_scheme : Bool
}

struct Meta {
  mut scheme_end : Int?
  mut auth_meta : AuthMeta?
  mut path_bounds : (Int, Int)
  mut query_end : Int?
} derive(Default)

struct AuthMeta {
  host_bounds : (Int, Int)
  host_meta : HostKind
}

pub enum HostKind {
  Ipv4
  Ipv6
  IpvFuture
  RegName
} derive(Eq, Show)

struct Parser {
  criteria : Criteria
  str : String
  mut pos : Int
  out : Meta
}

enum PathKind {
  General
  AbEmpty
  ContinuedNoScheme
}

enum Seg {
  Normal(Bool)
  Ellipsis
  MaybeV4(Bool)
  SingleColon
}

fn len(self : Parser) -> Int {
  self.str.length()
}

fn has_remaining(self : Parser) -> Bool {
  self.pos < self.len()
}

fn peek(self : Parser, i : Int) -> Char? {
  if self.pos + i < self.len() {
    Some(self.str[self.pos + i])
  } else {
    None
  }
}

fn skip(self : Parser, n : Int) -> Unit {
  self.pos += n
}

fn read(self : Parser, table : @table.T) -> Bool!ParseError {
  let start = self.pos
  self._read!(table, fn(_i, _ch) {  })
  self.pos > start
}

fn _read(
  self : Parser,
  table : @table.T,
  f : (Int, Char) -> Unit
) -> Unit!ParseError {
  let mut i = self.pos
  let allow_pct_encoded = table.allows_pct_encoded()
  while i < self.len() {
    let x = self.str[i]
    if allow_pct_encoded && x == '%' {
      if i + 2 >= self.len() {
        raise err(i, InvalidOctet)
      }
      let (hi, lo) = (self.str[i + 1], self.str[i + 2])
      if not(@table.hexdig.allows(hi) && @table.hexdig.allows(lo)) {
        raise err(i, InvalidOctet)
      }
      i += 3
    } else {
      let (ch, len) = next_char(self.str, i)
      if not(table.allows(ch)) {
        break
      }
      f(i, ch)
      i += len
    }
  }
  self.pos = i
}

fn read_str(self : Parser, s : String) -> Bool {
  if self.pos + s.length() > self.len() {
    return false
  }
  for i = 0; i < s.length(); i = i + 1 {
    if self.str[self.pos + i] != s[i] {
      return false
    }
  }
  self.skip(s.length())
  true
}

fn read_v6(self : Parser) -> Bool {
  let mut ellipsis_i = 8
  let mut i = 0
  while i < 8 {
    match self.read_v6_segment() {
      Some(Normal(colon)) => {
        if colon == (i == 0 || i == ellipsis_i) {
          return false
        }
        i += 1
      }
      Some(Ellipsis) => {
        if ellipsis_i != 8 {
          return false
        }
        ellipsis_i = i
      }
      Some(MaybeV4(colon)) => {
        if i > 6 || colon == (i == ellipsis_i) {
          return false
        }
        if not(self.read_v4()) {
          return false
        }
        i += 2
        break
      }
      Some(SingleColon) => return false
      None => break
    }
  }
  if ellipsis_i == 8 {
    if i != 8 {
      return false
    }
  } else if i == 8 {
    return false
  }
  true
}

fn read_v6_segment(self : Parser) -> Seg? {
  let colon = self.read_str(":")
  if not(self.has_remaining()) {
    return if colon { Some(SingleColon) } else { None }
  }
  let first = self.peek(0).unwrap()
  if not(@table.hexdig.allows(first)) {
    return if colon {
      if first == ':' {
        self.skip(1)
        Some(Ellipsis)
      } else {
        Some(SingleColon)
      }
    } else {
      None
    }
  }
  let mut i = 1
  while i < 4 {
    guard let Some(ch) = self.peek(i) else {
      _ => {
        self.skip(i)
        return None
      }
    }
    if @table.hexdig.allows(ch) {
      i += 1
      continue
    } else if ch == '.' {
      return Some(MaybeV4(colon))
    } else {
      break
    }
  }
  self.skip(i)
  Some(Normal(colon))
}

fn read_v4(self : Parser) -> Bool {
  if not(self.read_v4_octet()) {
    return false
  }
  for i = 0; i < 3; i = i + 1 {
    if not(self.read_str(".") && self.read_v4_octet()) {
      return false
    }
  }
  true
}

fn read_v4_octet(self : Parser) -> Bool {
  guard let Some(res) = self.peek_digit(0) else { _ => return false }
  if res == 0 {
    self.skip(1)
    return true
  }
  let mut res = res
  for i = 1; i < 3; i = i + 1 {
    guard let Some(x) = self.peek_digit(i) else {
      _ => {
        self.skip(i)
        return true
      }
    }
    res = res * 10 + x
  }
  self.skip(3)
  res < 256
}

fn peek_digit(self : Parser, i : Int) -> Int? {
  self.peek(i).filter(is_ascii_digit).map(fn(ch) { ch.to_int() - '0'.to_int() })
}

fn read_port(self : Parser) -> Unit {
  if self.read_str(":") {
    let mut i = 0
    while not(self.peek_digit(i).is_empty()) {
      i += 1
    }
    self.skip(i)
  }
}

fn read_ip_literal(self : Parser) -> HostKind?!ParseError {
  if not(self.read_str("[")) {
    return None
  }
  let start = self.pos
  let meta = if self.read_v6() {
    Ipv6
  } else if self.pos == start {
    self.read_ipv_future!()
    IpvFuture
  } else {
    raise err(start, InvalidIpv6Addr)
  }
  if not(self.read_str("]")) {
    raise err(self.pos, UnexpectedChar)
  }
  Some(meta)
}

fn read_ipv_future(self : Parser) -> Unit!ParseError {
  match self.peek(0) {
    Some('v' | 'V') => {
      self.skip(1)
      if self.read!(@table.hexdig) &&
        self.read_str(".") &&
        self.read!(@table.ipv_future) {
        return
      }
    }
    _ => ()
  }
  raise err(self.pos, UnexpectedChar)
}

fn select[T](self : Parser, for_uri : T, for_iri : T) -> T {
  if self.criteria.must_be_ascii {
    for_uri
  } else {
    for_iri
  }
}

fn read_v4_or_reg_name(self : Parser) -> HostKind!ParseError {
  let reg_name_table = self.select(@table.reg_name, @table.ireg_name)
  if self.read_v4() && not(self.read!(reg_name_table)) {
    Ipv4
  } else {
    RegName
  }
}

fn read_host(self : Parser) -> HostKind!ParseError {
  match self.read_ip_literal!() {
    Some(host) => host
    None => self.read_v4_or_reg_name!()
  }
}

fn parse_from_scheme(self : Parser) -> Unit!ParseError {
  let _ = self.read!(@table.scheme)
  if self.peek(0) == Some(':') {
    if self.pos > 0 && is_ascii_alphabetic(self.str[0]) {
      self.out.scheme_end = Some(self.pos)
    } else {
      raise err(0, UnexpectedChar)
    }
    self.skip(1)
    return if self.read_str("//") {
      self.parse_from_authority!()
    } else {
      self.parse_from_path!(General)
    }
  } else if self.criteria.must_have_scheme {
    raise err(self.pos, UnexpectedChar)
  } else if self.pos == 0 {
    if self.read_str("//") {
      return self.parse_from_authority!()
    }
  }
  self.parse_from_path!(ContinuedNoScheme)
}

fn parse_from_authority(self : Parser) -> Unit!ParseError {
  let mut host = (0, 0, RegName)
  let mut colon_cnt = 0
  let mut colon_i = 0
  let auth_start = self.pos
  let userinfo_table = self.select(@table.userinfo, @table.iuserinfo)
  self._read!(
    userinfo_table,
    fn(i, x) {
      if x == ':' {
        colon_cnt += 1
        colon_i = i
      }
    },
  )
  if self.peek(0) == Some('@') {
    self.skip(1)
    let host_start = self.pos
    let meta = self.read_host!()
    host = (host_start, self.pos, meta)
    self.read_port()
  } else if self.pos == auth_start {
    match self.read_ip_literal!() {
      Some(meta) => {
        host = (auth_start, self.pos, meta)
        self.read_port()
      }
      None => host = (self.pos, self.pos, RegName)
    }
  } else {
    let host_end = match colon_cnt {
      0 => self.pos
      1 => {
        for i = colon_i + 1; i < self.pos; i = i + 1 {
          if not(is_ascii_digit(self.str[i])) {
            raise err(i, UnexpectedChar)
          }
        }
        colon_i
      }
      _ => raise err(colon_i, UnexpectedChar)
    }
    let prev_pos = self.pos
    self.pos = auth_start
    let meta = if self.read_v4() && self.pos == host_end {
      Ipv4
    } else {
      RegName
    }
    self.pos = prev_pos
    host = (auth_start, host_end, meta)
  }
  self.out.auth_meta = Some(
    { host_bounds: (host.0, host.1), host_meta: host.2 },
  )
  self.parse_from_path!(AbEmpty)
}

fn parse_from_path(self : Parser, kind : PathKind) -> Unit!ParseError {
  let path_table = self.select(@table.path, @table.ipath)
  self.out.path_bounds = match kind {
    General => {
      let start = self.pos
      let _ = self.read!(path_table)
      (start, self.pos)
    }
    AbEmpty => {
      let start = self.pos
      if self.read!(path_table) && self.str[start] != '/' {
        raise err(start, UnexpectedChar)
      }
      (start, self.pos)
    }
    ContinuedNoScheme => {
      let segment_table = self.select(
        @table.segment_nz_nc, @table.isegment_nz_nc,
      )
      let _ = self.read!(segment_table)
      if self.peek(0) == Some(':') {
        raise err(self.pos, UnexpectedChar)
      }
      let _ = self.read!(path_table)
      (0, self.pos)
    }
  }
  if self.read_str("?") {
    let query_table = self.select(@table.query, @table.iquery)
    let _ = self.read!(query_table)
    self.out.query_end = Some(self.pos)
  }
  if self.read_str("#") {
    let fragment_table = self.select(@table.fragment, @table.ifragment)
    let _ = self.read!(fragment_table)

  }
  if self.has_remaining() {
    raise err(self.pos, UnexpectedChar)
  }
}
