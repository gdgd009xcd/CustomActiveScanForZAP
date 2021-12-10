# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
## 11 - 2021-12-11
### v0.5.5
- bugfix: There were false positive in the judgement code in 3-1,3-2
- maintenance: Updated log4j to the latest version

## 10 - 2021-12-02
### v0.5.4
- improve: Stop [Stop Active Scan] button is now supported
- maintenance: This repository is now checked at lgtm.com

## 9 - 2021-12-01
### v0.5.3
- maintenance: removed some redundant codes

## 8 - 2021-11-21
### v0.5.2
- bugfix: There was an false negative in the judgment code in 3-1
- improve: removed redundant code.(2-1, 2-2) because these codes are the same as 3-1, 3-2.
- maintenance: added new debuglevel DEBUGBINGO to LOG4J 

## 7 - 2021-09-26
### v0.5.1
- bugfix: there are some false positive at scan rule judgement

## 6 - 2021-09-18
### v0.5.0
- improve: Enhanced detection of small changes in page content
- new feature: detection of mongo db sql injection
## 5 - 2021-06-01
- improve: LOG4J prints stacktrace when sendAndReceive raises an exception
- bugfix: Set Multi-Release: true in the MANIFEST.MF file to use Java 9+
## 4 - 2020-11-16
### v0.0.5
- Header content is also included in the response when injection is detected.
- if response sizeody) < CustomSQLInjectionScanRule.MAXMASKBODYSIZE then, random id values convert to asterisk in response. This makes improve to detect small difference in response
## 3 - 2020-09-21
### v0.0.4
- changed addOnName, manifest.repo in .gradle.kts.
- help file added.
## 2 - 2020-09-17
### v0.0.3
- getId changed to 40037
## 1 - 2020-09-02

- first landing on github.




