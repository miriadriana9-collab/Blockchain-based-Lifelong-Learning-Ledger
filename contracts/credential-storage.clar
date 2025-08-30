;; CredentialStorage.clar
;; Core contract for storing and managing immutable learning credentials in the Lifelong Learning Ledger

;; Constants
(define-constant ERR-UNAUTHORIZED u100)
(define-constant ERR-CREDENTIAL-EXISTS u101)
(define-constant ERR-INVALID-HASH u102)
(define-constant ERR-INVALID-TITLE u103)
(define-constant ERR-INVALID-DESCRIPTION u104)
(define-constant ERR-NOT-FOUND u105)
(define-constant ERR-ALREADY-REVOKED u106)
(define-constant ERR-NOT-OWNER u107)
(define-constant ERR-INVALID-EXPIRY u108)
(define-constant ERR-METADATA-TOO-LONG u109)
(define-constant ERR-INVALID-CATEGORY u110)
(define-constant ERR-PAUSED u111)
(define-constant ERR-INVALID-ENDORSER u112)
(define-constant MAX-TITLE-LEN u100)
(define-constant MAX-DESCRIPTION-LEN u500)
(define-constant MAX-METADATA-LEN u1000)
(define-constant MAX-TAGS u10)

;; Data Variables
(define-data-var credential-counter uint u0)
(define-data-var contract-paused bool false)
(define-data-var contract-admin principal tx-sender)

;; Data Maps
(define-map credentials
  { credential-id: uint }
  {
    hash: (buff 32),              ;; SHA-256 hash of the credential data
    issuer: principal,            ;; Issuer principal
    learner: principal,           ;; Learner principal
    title: (string-ascii 100),    ;; Credential title
    description: (string-ascii 500), ;; Description
    timestamp: uint,              ;; Issuance block height
    expiry: (optional uint),      ;; Optional expiry block height
    revoked: bool,                ;; Revocation status
    metadata: (string-ascii 1000) ;; Additional metadata (e.g., JSON string)
  }
)

(define-map credential-hashes
  { hash: (buff 32) }
  { credential-id: uint }
)

(define-map endorsements
  { credential-id: uint, endorser: principal }
  {
    endorsement-note: (string-ascii 200),
    timestamp: uint
  }
)

(define-map categories
  { credential-id: uint }
  {
    category: (string-ascii 50),
    tags: (list 10 (string-ascii 20))
  }
)

(define-map access-grants
  { credential-id: uint, grantee: principal }
  { granted-at: uint, expires-at: (optional uint) }
)

;; Private Functions
(define-private (is-admin (caller principal))
  (is-eq caller (var-get contract-admin))
)

(define-private (is-issuer (caller principal) (credential-id uint))
  (match (map-get? credentials { credential-id: credential-id })
    cred (is-eq (get issuer cred) caller)
    false
  )
)

(define-private (is-learner (caller principal) (credential-id uint))
  (match (map-get? credentials { credential-id: credential-id })
    cred (is-eq (get learner cred) caller)
    false
  )
)

(define-private (hash-exists (hash (buff 32)))
  (is-some (map-get? credential-hashes { hash: hash }))
)

(define-private (increment-counter)
  (let ((current (var-get credential-counter)))
    (var-set credential-counter (+ current u1))
    (+ current u1)
  )
)

;; Public Functions

;; Store a new credential
(define-public (store-credential 
  (hash (buff 32)) 
  (issuer principal) 
  (learner principal) 
  (title (string-ascii 100)) 
  (description (string-ascii 500))
  (expiry (optional uint))
  (metadata (string-ascii 1000)))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (is-eq tx-sender issuer) (err ERR-UNAUTHORIZED)) ;; Only issuer can store
    (asserts! (> (len hash) u0) (err ERR-INVALID-HASH))
    (asserts! (and (> (len title) u0) (<= (len title) MAX-TITLE-LEN)) (err ERR-INVALID-TITLE))
    (asserts! (<= (len description) MAX-DESCRIPTION-LEN) (err ERR-INVALID-DESCRIPTION))
    (asserts! (<= (len metadata) MAX-METADATA-LEN) (err ERR-METADATA-TOO-LONG))
    (asserts! (not (hash-exists hash)) (err ERR-CREDENTIAL-EXISTS))
    (let
      (
        (credential-id (increment-counter))
      )
      (map-set credentials
        { credential-id: credential-id }
        {
          hash: hash,
          issuer: issuer,
          learner: learner,
          title: title,
          description: description,
          timestamp: block-height,
          expiry: expiry,
          revoked: false,
          metadata: metadata
        }
      )
      (map-set credential-hashes { hash: hash } { credential-id: credential-id })
      (ok credential-id)
    )
  )
)

;; Revoke a credential
(define-public (revoke-credential (credential-id uint))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (match (map-get? credentials { credential-id: credential-id })
      cred 
      (begin
        (asserts! (is-issuer tx-sender credential-id) (err ERR-UNAUTHORIZED))
        (asserts! (not (get revoked cred)) (err ERR-ALREADY-REVOKED))
        (map-set credentials
          { credential-id: credential-id }
          (merge cred { revoked: true })
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

;; Add endorsement to a credential
(define-public (add-endorsement (credential-id uint) (note (string-ascii 200)))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (match (map-get? credentials { credential-id: credential-id })
      cred 
      (begin
        (asserts! (not (get revoked cred)) (err ERR-ALREADY-REVOKED))
        ;; Assuming endorser is any principal, but could add checks
        (map-set endorsements
          { credential-id: credential-id, endorser: tx-sender }
          {
            endorsement-note: note,
            timestamp: block-height
          }
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

;; Add category and tags to credential
(define-public (add-category (credential-id uint) (category (string-ascii 50)) (tags (list 10 (string-ascii 20))))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (match (map-get? credentials { credential-id: credential-id })
      cred 
      (begin
        (asserts! (or (is-issuer tx-sender credential-id) (is-learner tx-sender credential-id)) (err ERR-UNAUTHORIZED))
        (asserts! (> (len category) u0) (err ERR-INVALID-CATEGORY))
        (map-set categories
          { credential-id: credential-id }
          { category: category, tags: tags }
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

;; Grant access to view private credential details
(define-public (grant-access (credential-id uint) (grantee principal) (expires-at (optional uint)))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (match (map-get? credentials { credential-id: credential-id })
      cred 
      (begin
        (asserts! (is-learner tx-sender credential-id) (err ERR-UNAUTHORIZED))
        (map-set access-grants
          { credential-id: credential-id, grantee: grantee }
          { granted-at: block-height, expires-at: expires-at }
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

;; Admin functions
(define-public (pause-contract)
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-paused true)
    (ok true)
  )
)

(define-public (unpause-contract)
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-paused false)
    (ok true)
  )
)

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-admin new-admin)
    (ok true)
  )
)

;; Read-only Functions

(define-read-only (get-credential-details (credential-id uint))
  (map-get? credentials { credential-id: credential-id })
)

(define-read-only (get-credential-by-hash (hash (buff 32)))
  (match (map-get? credential-hashes { hash: hash })
    entry (get-credential-details (get credential-id entry))
    none
  )
)

(define-read-only (get-endorsement (credential-id uint) (endorser principal))
  (map-get? endorsements { credential-id: credential-id, endorser: endorser })
)

(define-read-only (get-category (credential-id uint))
  (map-get? categories { credential-id: credential-id })
)

(define-read-only (has-access (credential-id uint) (viewer principal))
  (match (map-get? access-grants { credential-id: credential-id, grantee: viewer })
    grant 
    (match (get expires-at grant)
      exp (if (> block-height exp) false true)
      true
    )
    false
  )
)

(define-read-only (is-valid-credential (credential-id uint))
  (match (map-get? credentials { credential-id: credential-id })
    cred 
    (and 
      (not (get revoked cred))
      (match (get expiry cred)
        exp (< block-height exp)
        true
      )
    )
    false
  )
)

(define-read-only (get-counter)
  (var-get credential-counter)
)

(define-read-only (is-contract-paused)
  (var-get contract-paused)
)