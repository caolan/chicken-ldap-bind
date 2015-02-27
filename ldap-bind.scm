(module ldap-bind

(ldap-initialize ldap-bind ldap-unbind)

(import chicken scheme foreign)
(use data-structures irregex)

(foreign-declare "#include <ldap.h>")

(define-foreign-type ldap (c-pointer (struct "ldap")))

(define-foreign-variable ldap-success int LDAP_SUCCESS)
(define-foreign-variable ldap-invalid-credentials int LDAP_INVALID_CREDENTIALS)
(define-foreign-variable ldap-version-3 int LDAP_VERSION3)
(define-foreign-variable ldap-option-protocol-version int LDAP_OPT_PROTOCOL_VERSION)

(define-foreign-variable ldap-opt-success int LDAP_OPT_SUCCESS)

(define-record ldap-connection
  pointer)

(define ldap-versions
  `((1 . ,(foreign-value LDAP_VERSION1 int))
    (2 . ,(foreign-value LDAP_VERSION2 int))
    (3 . ,(foreign-value LDAP_VERSION3 int))))

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
                       (car p)
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

(define (verify-connection! location conn)
  (unless (ldap-connection-pointer conn)
    (error location "LDAP connection is already unbound")))

(define (ldap-option-set! ldap option value)
  (let ((result ((foreign-lambda int ldap_set_option ldap int c-pointer)
                 ldap option value)))
    (or (= result ldap-success)
        (error 'ldap-option-set! "An error occured setting an LDAP option" result))))

(define (ldap-initialize uris #!optional (version 3))
  (let ((uris (if (list? uris) (string-intersperse uris) uris)))
    (let-location ((connection (c-pointer ldap))
                   (version int (alist-ref version ldap-versions)))

      ((ldap-lambda 'ldap-initialize (ldap_initialize (c-pointer ldap) c-string))
       (location connection) uris)

      (ldap-option-set! connection
                        (foreign-value LDAP_OPT_PROTOCOL_VERSION int) 
                        (location version))
      
      (set-finalizer! (make-ldap-connection connection)
                      (lambda (c)
                        (and (ldap-connection-pointer c)
                             (ldap-unbind c)))))))

(define (ldap-bind conn dn pass)
  (verify-connection! 'ldap-bind conn)
  (= ldap-success
     ((ldap-lambda 'ldap-bind
                   (ldap_simple_bind_s ldap c-string c-string)
                   ldap-invalid-credentials)
      (ldap-connection-pointer conn) (->dn dn) pass)))

(define (ldap-unbind conn)
  (verify-connection! 'ldap-unbind conn)
  ((ldap-lambda 'ldap-unbind (ldap_unbind ldap))
   (ldap-connection-pointer conn))
  (ldap-connection-pointer-set! conn #f))

)