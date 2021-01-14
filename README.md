# KERIGO
Go implementation of KERI  (Key Event Receipt Infrastructure)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/decentralized-identity/kerigo/master/LICENSE)
![Go Version](https://img.shields.io/github/go-mod/go-version/decentralized-identity/kerigo)
![Build](https://github.com/decentralized-identity/kerigo/workflows/Build/badge.svg)
[![codecov](https://codecov.io/gh/decentralized-identity/kerigo/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/kerigo)
[![Go Report Card](https://goreportcard.com/badge/github.com/decentralized-identity/kerigo)](https://goreportcard.com/report/github.com/decentralized-identity/kerigo)
# Introduction

KERIGO is an open source go implementation of the [ Key Event Receipt Infrastructure (KERI) ](https://github.com/decentralized-identity/keri), a system designed to provide a secure identifier-based trust spanning layer for any stack. [The current version of the KERI paper can be found here](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).

KERI provides the same security and verifiability properties for transactions as a blockchain or distributed ledger can, without the overhead of requiring an absolute global ordering of transactions. Because of this, there is no need for a cannonical chain and thus there is no "KERI Chain" or "KERI Network". KERI Identifiers can be generated independantly in a self-sovereign and privacy-preserving manner and are secured via a self-certifying post-quantum resistant key management scheme based on blinded pre-rotation, auditable and flexible key events and a distributed conflict resolution algorithm called KAACE.

# Features

Currently work is focused on providing a libray that implements the core logic and data structures for creating and interacting with KERI infrastructure. A future goal is to implement runnable services that make up the actual KERI infrastructure (Witnesses, Validators, etc.).