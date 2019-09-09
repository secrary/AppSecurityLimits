# AppSecurityLimits

### IDEA:
Define security-related limits for an executable and  embed them into the application, `EDR`/`AV` products are responsible for retrieving the data at execution time and limit the application behavior based on the limits.

`The tool aims to limit exploit capabilities.`

# Implementation

## Developer's role:
Run `AppSecurityLimits.exe` with an executable path and location of the `JSON` file.
The tool creates `.appsec` section in the executable and inserts the `JSON` config file into the section.

![section](https://user-images.githubusercontent.com/16405698/64543392-cd212000-d32d-11e9-9226-7df3cefed887.png)


## EDR/AV's role:
If an executable contains `.appsec` section and a magic string is `.appseclimits_` then extract a `JSON` content from the section and control the application behavior accordingly.

![python](https://user-images.githubusercontent.com/16405698/64543242-8c290b80-d32d-11e9-9f5f-969675ca1e6e.png)


For Example, if a `JSON` content contains following field:
` { ... "remote_process_access" : false, ... }`
then an `EDR/AV` product should deny calls like `WriteRemoteProcess` since it's not intended to be used according to the application developer.

![json](https://user-images.githubusercontent.com/16405698/64544770-3efa6900-d330-11e9-9afe-0a7b5dd3c868.png)
