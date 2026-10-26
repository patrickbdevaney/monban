// Must be refused at startup: parse error (unterminated policy).
@id("bad")
forbid(principal, action, resource when { true };
