# 3.1.5

2024-02-23

* fixed NoSectionError for site url not being wrappted into FaultUnavailable

# 3.1.4

2024-02-23

* refactor credential loading so other code can access it


# 3.1.3

2023-02-18

* improved logging for unavailable secrets


# 3.1.2

2022-07-11

* fixed premature execution of `pass_command`


# 3.1.1

2022-01-14

* fixed connection errors not being raised as FaultUnavailable


# 3.1.0

2021-02-09

* added `pass_command`


# 3.0.0

2020-06-22

* added compatibility with BundleWrap >=4
* removed compatibility with Python <3.6


# 2.1.0

2018-05-16

* path to config file can now be overridden using env var BW_TEAMVAULT_SECRETS_FILE
* fetching secrets is now shown in `bw` progress line


# 2.0.1

2016-03-19

* keep HTTP connections alive


# 2.0.0

2016-03-18

* API changes
* items with missing secrets can now be skipped by bw 2.3.0+
* dummy usernames are now lowercase


# 1.0.0

2016-02-22

* initial release
