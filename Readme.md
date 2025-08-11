## Password-Hardened Encryption Revisited — Attack Demonstration

This repository contains an implementation demonstrating that the  
[Virgil Security PHE (Password-Hardened Encryption) protocol](https://github.com/VirgilSecurity/virgil-phe-go)  
can be broken in the **semi-adaptive corruption model**.

The attack and its analysis are based on our paper:

> **Password-Hardened Encryption Revisited**  
> Ruben Baecker, Paul Gerhart, and Dominique Schröder  
> ASIACRYPT 2025

### Overview

The original PHE protocol by Virgil Security is secure under **static corruption**,  
where the adversary chooses which parties to corrupt before the protocol starts.  
However, in a **semi-adaptive corruption model** — where the adversary may corrupt  
participants during protocol execution — we show that the scheme is vulnerable.

This repository contains:
- A minimal reproduction of the PHE protocol (selected components from Virgil’s SDK).
- Our attack implementation exploiting the semi-adaptive model.
- Test cases demonstrating the break.


### Usage

1. Clone the repository.
2. Run the attack simulation: `
   go run attack.go`
3.	Inspect the test output to see the brute-forced passwords under semi-adaptive corruption.






### Attribution & Licenses

#### Virgil Security PHE Go SDK (BSD-3-Clause)

This repo includes an adapted file derived from the Virgil Security PHE Go SDK:

- `utils/utils.go`

It carries the original BSD-3-Clause notice and an added **NOTICE** header explaining that it’s adapted solely
for testing/reproduction. The original upstream project is:

- Virgil Security PHE Go SDK: https://github.com/VirgilSecurity/virgil-phe-go

**Copyright (C) 2015–2019 Virgil Security Inc.**  
Redistribution terms follow the BSD-3-Clause license. See `utils/utils.go` header.

#### Password List (SecLists)

This project includes the following password list for testing purposes:

- [`passwords.txt`](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt)  
  From the [SecLists project](https://github.com/danielmiessler/SecLists) by Daniel Miessler.  
  License: [Creative Commons Attribution-ShareAlike 4.0 International](https://github.com/danielmiessler/SecLists/blob/master/LICENSE).

Please note: this list is used for **local testing only**. Follow the license terms if you redistribute it.

#### This Repository (MIT)

All original code in this repository is under the **MIT License**.


### Responsible Use

- The code is for **research and reproducibility**.
- Do not target third-party systems.
- Follow coordinated disclosure practices when appropriate.
