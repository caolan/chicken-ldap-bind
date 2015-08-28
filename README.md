# ldap-bind

A CHICKEN egg implementing LDAP bind for authentication purposes using
the OpenLDAP library. This is no a complete binding to the OpenLDAP
library and only covers the authentication use-case.

Requires OpenLDAP / libldap and liblber to be installed.

## API

#### (ldap-initialize uris #!optional (version 3))

Initializes the LDAP library and opens a connection to an LDAP server.
Returns an ldap-connection record.

#### (ldap-bind conn dn pass)

Attempts to bind to a dn using the given password. The conn argument is
a connection record returned from ldap-initialize. Returns #t if the
bind succeeded, #f otherwise.

#### (ldap-unbind conn)

Terminate the current association, and free the resources contained in
the connecction record. After calling ldap-unbind the connection to
the LDAP server is closed and the connection record becomes invalid.

## Example

```scheme
(use ldap-bind)

(define ld (ldap-initialize "ldaps://example.com"))

(if (ldap-bind "uid=testuser,cn=users,dc=example,dc=com" "password")
  (print "Welcome, authenticated user!")
  (print "Invalid Credentials"))

;; or, using list syntax for a base dn:

(define base-dn
  '((cn "users") (dc "example") (dc "com")))

(if (ldap-bind (cons '(uid "testuser") base-dn) "password")
  (print "Welcome, authenticated user!")
  (print "Invalid Credentials"))

(ldap-unbind ld)
```

## Author

Original implementation work by Moritz Heidkamp, updated to latest APIs
and released with just the ldap-bind feature by Caolan McMahon (with kind
permission).
