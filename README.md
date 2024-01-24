# Awesome Stacks Security

## Contents


### Intro

While reviewing Clarity smart contract audits, we've noticed several easily identifiable issues of varying severity that often divert the auditor's attention from more logically complex findings, consuming valuable time.

This situation presents a mutual disadvantage for both developers and auditors, as it hinders productivity and adds challenges to the auditing process for identifying and addressing more critical problems.

Developers often allocate a significant amount of time to the mitigation process, focusing on implementing fixes for trivial issues. As a result, they have less time available to address more complex and challenging issues.

Auditors often find themselves spending more time reporting these easy to spot issues, which reduces the time they can dedicate to exploring edge cases and addressing more in-depth problems within the allotted timeline.

We have created a checklist of issues that projects should look for before undergoing audits. This guide covers both vulnerabilities and best practices commonly seen reported in Stacks audits.

---

### Missing threshold check

When appropriate, authenticated functions should include threshold checks to minimize centralization risk.

For example, the following is a smart contract that charges a fixed fee when users withdraw their tokens. The owner has the ability to set the fee amount to any value:

```clarity
...
(define-data-var fee uint u100)

(define-public (set-fee (new-fee uint))
  (begin
    (try! (is-owner))
    (ok (var-set fee new-fee))
  )
)
```

If the owner's wallet is compromised or controlled by a malicious entity, there is a risk of a DoS attack. This can happen if the attacker sets the fee to an excessively large amount.

This centralization issue can be minimized by including a threshold check in the `set-fee` function:

```clarity
...
(define-data-var fee uint u100)

(define-public (set-fee (new-fee uint))
  (begin
    (try! (is-owner))
    ;; threshold check
    (asserts! (<= new-fee u1000) (err u1))
    (ok (var-set fee new-fee))
  )
)
```

While `clarinet check` throws a warning on potentially unchecked data, it's common for developers to ignore this and go under the assumption privileged users shall always act accordingly, thus leading to centralization risks throughout the protocol.

---

### Lack of access control

Developers should ensure that all authenticated public functions have proper access control in place.

For instance, if a function responsible for changing the owner of a contract lacks access control, anyone can call it and change the owner to themselves:

```clarity
...
(define-public (change-owner (new-owner principal))
  (ok (var-set owner new-owner))
)
```

However, even when access control is present, developers should question whether the current authorizations are suitable from a centralization standpoint.

For instance, developers should consider whether a sensitive action should be performed by an owner role or if it would be better executed through a DAO or a multisig-like structure.

Without thorough documentation of the protocol design, it's challenging to accurately evaluate access control and centralization risks that arise from it. We advise developers to create a list of interactions and authorized roles for each interaction.

---

### Frontrunning issues

Transactions can be viewed in the mempool before they are included in a block.

For example, this `withdraw` function takes a password and its sha256 hash is checked for correctness before proceeding :

```clarity
...
(define-public (withdraw (password uint))
    (let
        ((caller contract-caller)) 
        (asserts! (is-eq (sha256 password) 0x4df4b098a0c96a77a64bd4a2c18e60ea9b29d4b24ffd3475729e6bc013fc40cd) (err u1337))
        (as-contract (stx-transfer? u1000 tx-sender caller))
    )
)
```

However, an attacker can monitor the mempool for a transaction that calls withdraw with a correct password and then frontrun that transaction to withdraw the funds before it.

This issue can be addressed by splitting the withdrawal process into two separate transactions.

To address this issue, the withdrawal process can be modified as follows: 
First, a user initiates a withdrawal request, allowing only one user to request a withdrawal at a time. Additionally, a small fee can be charged during the request, which will later be returned to the user upon the actual withdrawal. This approach discourages attackers from requesting a withdrawal without prior knowledge of the password causing a DoS.

After the request is made, a user can verify if their withdrawal request was successful. During a certain block period following the request, only the user who successfully made the request can call the withdraw function. If attackers attempt to frontrun this transaction, their transactions will revert as they have not successfully requested the withdrawal.

---

### Use contract-caller instead of tx-sender for authentication purposes

Although this is a well-known issue in Solidity smart contracts, many Stacks smart contracts written in Clarity still utilize tx-sender for authentication. 

It's important to note that using tx-sender for authentication can leave the contract vulnerable to phishing attacks.  

Vulnerable contract (`vulnerable-auth.clar`): 
```clarity
(define-constant ERR-NOT-OWNER (err u1))

(define-data-var owner principal tx-sender)

(define-public (change-owner (new-owner principal))
  (begin
    (try! (is-owner))
  	(ok (var-set owner new-owner))
  )
)

(define-read-only (get-owner)
    (ok (var-get owner))
)

(define-private (is-owner)
    (ok (asserts! (is-eq tx-sender (var-get owner)) ERR-NOT-OWNER))
)
```

Phishing contract :
```clarity
(define-public (phish)
  (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.vulnerable-auth change-owner (as-contract tx-sender))
)
```

An attacker can trick the victim who is the owner of the `vulnerable-auth` contract into calling the phishing contract that will call `change-owner` in `vulnerable-auth`.

As `vulnerable-auth` uses `tx-sender` for authentication, this call will successfully change the owner to whatever the phishing contract set as the argument (in this case, the contract principal of the phishing contract).

Therefore, it is recommended to use `contract-caller` instead of `tx-sender` for authentication.

---

### Signature replay

If a function uses a signature for authentication, it's important to check whether appropriate signature replay mitigations are in place.

Additionally, it is recommended to include a nonce in the message that will be hashed and verify the validity of the nonce.

Example: 
```clarity
(define-read-only (check-signature (msgHash (buff 32)) (signature (buff 65)))
    (begin
        (asserts! (is-eq (unwrap! (secp256k1-recover? msgHash signature) (err u1)) owner) (err u2))
        (ok true)
    )
)
```

In the example above, they're only checking if the signature is valid, so even if the signature has already been used, it will pass the check.

As a result, attackers can search for signatures from previous transactions that call the `check-signature` function and replay those used signatures on the contract.

---

### Weak randomness

It is not recommended to use randomness generated from block-related data.

Example: 
```clarity
(define-read-only (weak-prng-read)
    (let 
        (
            (blockHash (unwrap! (get-block-info? id-header-hash (- block-height u1)) (err u1)))
            (num (buff-to-uint-be (unwrap! (as-max-len? (unwrap! (slice? (sha256 blockHash) u0 u16) (err u2) ) u16) (err u3))))
        )
        (ok num)
    )
)
```

In this example, a random number is generated using the block hash as a source of randomness.

However, if there are other functions in the codebase that rely on the `weak-prng-read` function to generate random numbers, this can introduce potential issues.
 
For instance, if the contract rewards the user based on correctly guessing a number generated by the `weak-prng-read` function, it can be predicted by utilizing another smart contract to make the call.

Because smart contracts written in Clarity can access the Stacks blockchain's verifiable random function, it is recommended to use the Stacks VRF instead of relying on something like block data for randomness.

---

## Best Practices

### Unnecessary begin

If a function consists of only one expression, using `begin` is unnecessary and serves no purpose other than increasing the execution cost.

Example: 
```clarity
(define-public (with-begin)
    (begin
        (ok true)
    )
)

(define-public (without-begin)
    (ok true)
)
```

Cost comparison: 
```
>> ::get_costs (contract-call? .unnecessary-begin with-begin)
+----------------------+----------+------------+------------+
|                      | Consumed | Limit      | Percentage |
+----------------------+----------+------------+------------+
| Runtime              | 816      | 5000000000 | 0.00 %     |
+----------------------+----------+------------+------------+
| Read count           | 3        | 15000      | 0.02 %     |
+----------------------+----------+------------+------------+
| Read length (bytes)  | 350      | 100000000  | 0.00 %     |
+----------------------+----------+------------+------------+
| Write count          | 0        | 15000      | 0.00 %     |
+----------------------+----------+------------+------------+
| Write length (bytes) | 0        | 15000000   | 0.00 %     |
+----------------------+----------+------------+------------+

(ok true)

>> ::get_costs (contract-call? .unnecessary-begin without-begin)
+----------------------+----------+------------+------------+
|                      | Consumed | Limit      | Percentage |
+----------------------+----------+------------+------------+
| Runtime              | 649      | 5000000000 | 0.00 %     |
+----------------------+----------+------------+------------+
| Read count           | 3        | 15000      | 0.02 %     |
+----------------------+----------+------------+------------+
| Read length (bytes)  | 350      | 100000000  | 0.00 %     |
+----------------------+----------+------------+------------+
| Write count          | 0        | 15000      | 0.00 %     |
+----------------------+----------+------------+------------+
| Write length (bytes) | 0        | 15000000   | 0.00 %     |
+----------------------+----------+------------+------------+

(ok true)
```

It is recommended to remove the `begin` keyword if a function contains only one expression.

---

### Unnecessary begin

If a function consists of only one expression, using `begin` is unnecessary and serves no purpose other than increasing the execution cost.

Example: 
```clarity
(define-public (with-begin)
    (begin
        (ok true)
    )
)

(define-public (without-begin)
    (ok true)
)
```

Cost comparison: 
```
>> ::get_costs (contract-call? .unnecessary-begin with-begin)
+----------------------+----------+------------+------------+
|                      | Consumed | Limit      | Percentage |
+----------------------+----------+------------+------------+
| Runtime              | 816      | 5000000000 | 0.00 %     |
+----------------------+----------+------------+------------+
| Read count           | 3        | 15000      | 0.02 %     |
+----------------------+----------+------------+------------+
| Read length (bytes)  | 350      | 100000000  | 0.00 %     |
+----------------------+----------+------------+------------+
| Write count          | 0        | 15000      | 0.00 %     |
+----------------------+----------+------------+------------+
| Write length (bytes) | 0        | 15000000   | 0.00 %     |
+----------------------+----------+------------+------------+

(ok true)

>> ::get_costs (contract-call? .unnecessary-begin without-begin)
+----------------------+----------+------------+------------+
|                      | Consumed | Limit      | Percentage |
+----------------------+----------+------------+------------+
| Runtime              | 649      | 5000000000 | 0.00 %     |
+----------------------+----------+------------+------------+
| Read count           | 3        | 15000      | 0.02 %     |
+----------------------+----------+------------+------------+
| Read length (bytes)  | 350      | 100000000  | 0.00 %     |
+----------------------+----------+------------+------------+
| Write count          | 0        | 15000      | 0.00 %     |
+----------------------+----------+------------+------------+
| Write length (bytes) | 0        | 15000000   | 0.00 %     |
+----------------------+----------+------------+------------+

(ok true)
```

It is recommended to remove the `begin` keyword if a function contains only one expression.

---

### Unnecessary if statements

In certain cases, if we are solely performing checks, it is possible to replace `if` statements with `asserts!` or `try!` for improved readability and conciseness.

For example: 
```clarity
(define-public (divide (num0 uint) (num1 uint))
    (if (not (is-eq num1 u0))
        (ok (/ num0 num1))
        err-division-by-zero
    )
)
```
```clarity
(define-public (divide (num0 uint) (num1 uint))
    (begin
        (asserts! (not (is-eq num1 u0)) err-division-by-zero)
        (ok (/ num0 num1))
    )
)
```

Often, unnecessary if statements and nesting can introduce complexity to smart contracts, which can be avoided to maintain simplicity and readability.

---

### Avoid using panic unwrap functions unless a prior check is present

It is recommended to define constants for different errors and their corresponding error codes. When handling errors, it is preferable to use `unwrap!` and `unwrap-err!` with the error constant instead of using `unwrap-panic` and `unwrap-err-panic`. 

This approach provides more informative error messages with error codes to users, rather than generic runtime errors.

Example:
```clarity
(define-constant err-balance-not-set (err u1))

(define-map balances principal uint)
(map-set balances tx-sender u1000)

(define-public (get-balance (who principal))
    (ok (unwrap! (map-get? balances who) err-balance-not-set))
)

(define-public (get-balance-panic (who principal))
    (ok (unwrap-panic (map-get? balances who)))
)
```

