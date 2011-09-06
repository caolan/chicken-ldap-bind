(module openldap

(ldap-initialize ldap-bind)

(import chicken scheme foreign)
(use data-structures irregex)

(foreign-declare "#include <ldap.h>")

(define-foreign-type ldap (c-pointer (struct "ldap")))

(define-foreign-variable ldap-success int LDAP_SUCCESS)
(define-foreign-variable ldap-invalid-credentials int LDAP_INVALID_CREDENTIALS)
(define-foreign-variable ldap-version-3 int LDAP_VERSION3)
(define-foreign-variable ldap-option-protocol-version int LDAP_OPT_PROTOCOL_VERSION)

(define-record ldap-connection
  pointer)

(foreign-code "
int protocol = LDAP_VERSION3;
ldap_set_option( NULL, LDAP_OPT_PROTOCOL_VERSION, &protocol );
")

(define ldap-error->string
  (foreign-lambda c-string ldap_err2string int))

(define (backslash-escape m)
  (string-append "\\" (irregex-match-substring m)))

(define (escape-dn-value value)
  (let* ((value (or (irregex-replace '(seq bos (" #")) value backslash-escape) value))
         (value (or (irregex-replace '(seq #\space eos) value backslash-escape) value)))
    (irregex-replace/all '("\"+,;<=>\\") value backslash-escape)))

(define (->dn val)
  (if (list? val)
      (string-intersperse
       (map (lambda (p)
              (sprintf "~A=~A"
                       (symbol->string (car p))
                       (string-intersperse (map escape-dn-value (cdr p)) "+")))
            val)
       ",")
      val))

(define-syntax ldap-lambda
  (syntax-rules ()
    ((_ location (fargs ...) ignore-result ...)
     (lambda args
       (let ((result (apply (foreign-lambda int fargs ...) args)))
         (unless (memq result (list ldap-success ignore-result ...))
           (error location (ldap-error->string result)))
         result)))))

(define (ldap-initialize uris)
  (let ((uris (if (list? uris) (string-intersperse uris) uris)))
    (let-location ((connection (c-pointer ldap)))
      ((ldap-lambda 'ldap-initialize (ldap_initialize (c-pointer ldap) c-string))
       (location connection) uris)
      (make-ldap-connection connection))))

(define (ldap-bind conn dn pass)
  (= ldap-success
     ((ldap-lambda 'ldap-bind
                   (ldap_simple_bind_s ldap c-string c-string)
                   ldap-invalid-credentials)
      (ldap-connection-pointer conn) (->dn dn) pass)))

)