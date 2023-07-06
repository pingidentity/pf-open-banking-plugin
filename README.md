PingFederate Open Banking Software Assertion Validator
======================================================

### Overview

The PingFederate Open Banking Software Assertion Validator plug-in implements a policy that aligns to the guidelines set forth in the Open Banking OpenID Dynamic Client Registration Specification, as part of the [Open Banking UK Profiles for API Security](https://bitbucket.org/openid/obuk).

Compiling this source and configuring an instance of the resulting plug-in within PingFederate will ensure that all dynamic client registration requests received are securely validated before allowing the client to be created. The plug-in provides some configuration options to alter how the issuer and signature are validated.

### System requirements and dependencies

* PingFederate 11.3 or higher
* PingFederate 9.3 support is available at [9.3](https://github.com/pingidentity/open-banking-plugin/tree/9.3) branch
* PingFederate 9.2 support is available at [9.2](https://github.com/pingidentity/open-banking-plugin/tree/9.2) branch 
* PingFederate 9.1 support is available at [9.1](https://github.com/pingidentity/open-banking-plugin/tree/9.1) branch 
* PingFederate 9.0 support is available at [9.0](https://github.com/pingidentity/open-banking-plugin/tree/9.0) branch 

### Installation

* Copy the source from `src/main/java` to the PingFederate server's SDK examples folder: `<PF_INSTALL>/pingfederate/sdk/plugin-src/open-banking-plugin/java`
* Follow the build instructions in the [PingFederate SDK Developer's Guide](https://documentation.pingidentity.com/pingfederate/pf90/index.shtml#sdkDevelopersGuide/concept/buildingAndDeployingYourProject.html) to compile and deploy the plug-in.
* Restart PingFederate.
* When running in a clustered environment, ensure that the resulting plug-in .jar file is copied into every node under: `<PF_INSTALL>/pingfederate/server/default/deploy`. Restart each PingFederate node to ensure the plug-in is loaded.

### Configuration

* In the PingFederate administrative console, navigate to: OAuth Settings > Client Settings
* Follow the configuration steps to enable Dynamic Client Registration. At the Client Registration Policy step, define an instance of the Open Banking Software Assertion Validator and add it to the list of enabled policies.
* The Open Banking Software Assertion Validator may be combined with instances of other policy plug-in types, such as the Response Type Constraints. When doing so, the Open Banking Software Assertion Validator must be the first policy plug-in defined in the list as it is responsible for digesting the JWT payload and converting that to the internal client representation passed to subsequent policy plug-ins instances.
* Save the Client Settings.
* When running in a clustered environment, be sure to replicate the configuration updates to other nodes.

### Support and reporting bugs

Please report issues using the project's [issue tracker](https://github.com/pingidentity/open-banking-plugin/issues).

### License

This project is licensed under the Apache License 2.0.
