pub struct Uri {
  val : String
  meta : Meta
}

pub struct Authority {
  val : String
  meta : AuthMeta
}

pub fn parse(str : String) -> Uri!ParseError {
  let parser : Parser = {
    criteria: { must_be_ascii: true, must_have_scheme: true },
    str,
    pos: 0,
    out: default(),
  }
  parser.parse_from_scheme!()
  { val: str, meta: parser.out }
}

pub fn scheme(self : Uri) -> String {
  let end = self.meta.scheme_end.or(0)
  self.val.substring(~end)
}

pub fn authority(self : Uri) -> Authority? {
  guard let Some(meta) = self.meta.auth_meta else { _ => return None }
  let start = match self.meta.scheme_end {
    Some(i) => i + 3
    None => 2
  }
  let end = self.meta.path_bounds.0
  Some(
    {
      val: self.val.substring(~start, ~end),
      meta: {
        host_bounds: (meta.host_bounds.0 - start, meta.host_bounds.1 - start),
        host_meta: meta.host_meta,
      },
    },
  )
}

pub fn userinfo(self : Authority) -> String? {
  let host_start = self.meta.host_bounds.0
  if host_start != 0 {
    Some(self.val.substring(end=host_start - 1))
  } else {
    None
  }
}

pub fn host(self : Authority) -> String {
  let (start, end) = self.meta.host_bounds
  self.val.substring(~start, ~end)
}

pub fn host_kind(self : Authority) -> HostKind {
  self.meta.host_meta
}

pub fn port(self : Authority) -> String? {
  let host_end = self.meta.host_bounds.1
  if host_end != self.val.length() {
    Some(self.val.substring(start=host_end + 1))
  } else {
    None
  }
}

pub fn path(self : Uri) -> String {
  self.val.substring(start=self.meta.path_bounds.0, end=self.meta.path_bounds.1)
}

pub fn query(self : Uri) -> String? {
  self.meta.query_end.map(
    fn(end) { self.val.substring(start=self.meta.path_bounds.1 + 1, ~end) },
  )
}

fn fragment_start(self : Uri) -> Int? {
  let query_or_path_end = self.meta.query_end.or(self.meta.path_bounds.1)
  if query_or_path_end != self.val.length() {
    Some(query_or_path_end + 1)
  } else {
    None
  }
}

pub fn fragment(self : Uri) -> String? {
  self.fragment_start().map(fn(i) { self.val.substring(start=i) })
}

pub fn output(self : Uri, logger : Logger) -> Unit {
  logger.write_string(self.val)
}

pub fn output(self : Authority, logger : Logger) -> Unit {
  logger.write_string(self.val)
}

pub fn to_string(self : Uri) -> String {
  self.val
}

pub fn to_string(self : Authority) -> String {
  self.val
}

test "parse" {
  let uri = parse!("foo://user@example.com:8042/over/there?name=ferret#nose")
  assert_eq!(uri.scheme(), "foo")
  let auth = uri.authority().unwrap()
  assert_eq!(auth.to_string(), "user@example.com:8042")
  assert_eq!(auth.userinfo(), Some("user"))
  assert_eq!(auth.host(), "example.com")
  assert_eq!(auth.host_kind(), RegName)
  assert_eq!(auth.port(), Some("8042"))
  assert_eq!(uri.path(), "/over/there")
  assert_eq!(uri.query(), Some("name=ferret"))
  assert_eq!(uri.fragment(), Some("nose"))
}
