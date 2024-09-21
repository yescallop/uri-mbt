// Taken from `moonbitlang/core/string/{string,utils}.mbt`

let min_leading_surrogate = 0xD800

let max_leading_surrogate = 0xDBFF

let min_trailing_surrogate = 0xDC00

let max_trailing_surrogate = 0xDFFF

fn is_leading_surrogate(c : Char) -> Bool {
  let code = c.to_int()
  min_leading_surrogate <= code && code <= max_leading_surrogate
}

fn is_trailing_surrogate(c : Char) -> Bool {
  let code = c.to_int()
  min_trailing_surrogate <= code && code <= max_trailing_surrogate
}

fn code_point_of_surrogate_pair(leading : Char, trailing : Char) -> Char {
  Char::from_int(
    (leading.to_int() - 0xD800) * 0x400 + trailing.to_int() - 0xDC00 + 0x10000,
  )
}

fn next_char(str : String, i : Int) -> (Char, Int) {
  let c1 = str[i]
  if is_leading_surrogate(c1) && i + 1 < str.length() {
    let c2 = str[i + 1]
    if is_trailing_surrogate(c2) {
      return (code_point_of_surrogate_pair(c1, c2), 2)
    }
  }
  return (c1, 1)
}

fn is_ascii_digit(ch : Char) -> Bool {
  ch >= '0' && ch <= '9'
}

fn is_ascii_alphabetic(ch : Char) -> Bool {
  (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
}
