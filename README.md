<<<<<<< HEAD
# Welcome to the SecBPMN2BC page!

SecBPMN2BC is a method created to support the design of *secure business processes* to be executed in blockchain. It is composed of a modelling language, a suggested workflow and a software tool that partially support the workflow by identifying conflicts and the part of the busines process that can be executed in blockchain.

This is the repository of SecBPMN2BC software tool, that supports the SecBPMN2BC medoth in identifing security and privity conflicts, and generating blockchain-related  properties for SecBPMN2 elements. This tool is based, and uses part of the libraries of on (STS-Tool)(https://www.sts-tool.eu).

## Repository content
This repostory contains:
* this guide
* the compiled version of the software tool 
* source code of the software tool
* compiled library of [STS-Tool](https://www.sts-tool.eu)
* a SecBPMn2BC example file, that can be used to try the tool.


## Requirements
This is the software configuration tested. Other software versions or operative systems are not supported.
* Eclispe 4.5.2
* Java 8
* Windows 10

## Installation and set-up instructions 
1. Download the last SecBPMN2BC zip file from here: https://github.com/MattiaSalnitri/SecBPMN2BC/releases
2. Copy the zip file inside Eclipse root directory and expand it there.
3. Start Eclipse
4. check if the plugin is installed: verify (do not click) if in the *File* -> *New* exists an element *SecBPMN2BC model*
5. Open SecBPMN2BC perspective: *Window* -> *Perspective* ->  *Open Perspective * -> *Other* -> *Secbpmn2bc


## Usage
The tool is a java-based application. 
To correctly use it we suggest to follow these steps:

1. Open eclipse with SecBNPMN2BC plugin installed.
2. Open the SecBPMN2 example files: *File* -> *Open File* and choose one of the SecBPMN2BC files in */documentation/examples*.
Your Eclipse interface should now be similar to the following screenshot:
![initial interface](https://github.com/MattiaSalnitri/SecBPMN2BC/blob/main/documentation/images/1-initialModel.png)
3. By selecting an element in the structure of the process in the main pane, the lower right pane will show its associated properties. For instance, the property Blockchain type of the Definitions element is currently set to Undefined.
4. If the console pane is not open in Eclipse, open it: *SecBPMN2BC Editor* -> *Show console*.
5. Automatically annotate the model with blockchain-related properties: *SecBPMn2BC Editor* -> *annotate with BC properties*.
![SecBPMN2BC menu](https://github.com/MattiaSalnitri/SecBPMN2BC/blob/main/documentation/images/2-openMenu.png)
6. Once the analisys is completed, a pop-up will confirm that the analysis is complete.
![analysis complete](https://github.com/MattiaSalnitri/SecBPMN2BC/blob/main/documentation/images/3-completedOk.png)
7. After the analysis is complete, blockchain-specific properties of each process element will be automatically set to the best value satisfying the security requirements. For instance, the property Blockchain type of the Definitions element for the model Running_example_V1 will be now set to Public.
![Element properies](https://github.com/MattiaSalnitri/SecBPMN2BC/blob/main/documentation/images/4-annotatedModel.png)


=======
# THES
>>>>>>> branch 'main' of https://github.com/laironx01/THES
