# Docker vulnerability AnalyZER (DAZER)
#### Deep dive into Docker images on Docker Hub
DAZER is a tool aiming at making the study of Docker Hub's security landscape available to anyone.

## Description
DAZER allows gathering metadata as well as vulnerability information about any typed set of Docker images (see getting started), allowing anyone to analyze Docker Hub's security landscape.

DAZER may be used to analyze multiple typed set of Docker images such as certified, verified, official and community images.
Note that a limited set of community images is however required, as analyzing almost 2 million images is out of this project's scope.

Running the DAZER software results into two Json files containing all the gathered information about the type of Docker images specified upon runtime, as well as their detailed vulnerabilities:

#### analysis.json
1. Image ID
2. Image type (official, certified, verified, community)
3. Whether the image is certified (certified images are verified, but not vice versa)
4. Image name
5. Image tag
6. Last updated
7. Total pulls
8. Vulnerabilities (list of CVE numbers)
9. Parent images (list of parents with name and tag)

#### vulnerabilities.json
1. CVE number
2. CWE number
3. Package name
4. Package version
5. Severity

Note that all the vulnerability information is retrieved by downloading each image composing the set of specified images (e.g. official images) and analyzing them with the famous vulnerability scanning tool known as Clair scanner.

Finally, the outputed Json files may be imported into a noSQL database such as MongoDB in order to query the gathered data and make sense of Docker Hub's security landscape. Note that we recommend using Redash for data mining, as it allows representing queries graphically.

## Caution/Disclaimer
This software has only been tested on Ubuntu 16.04.5 LTS and MacOS Mojave (version 10.14.2) and should be used with caution.
We are not responsible for any harm that it could cause to your system or Docker Hub's infrastructure.

## Requirements
- Ubuntu 16.04.5 LTS*: http://releases.ubuntu.com/16.04/ (required)  
- Python 3.6.x: https://www.python.org/downloads/ (required)
- Docker: https://www.docker.com/get-started (required)
- Clair scanner: https://github.com/arminc/clair-scanner (required)
- Valid Docker Hub credentials: https://hub.docker.com/signup (required)
- MongoDB: https://resources.mongodb.com/getting-started-with-mongodb (recommended)
- Redash: https://redash.io/help/open-source/setup (recommended)

*Note: more recent Ubuntu versions and other Debian-based distributions should also work but they have not been tested. 


<!--
## Requirements for Windows
- Git: https://git-scm.com/downloads
- Go: https://golang.org/doc/install
- Make: http://gnuwin32.sourceforge.net/packages/make.htm
- Dep: https://github.com/golang/dep/releases/download/v0.4.1/dep-windows-amd64.exe
- Docker: https://hub.docker.com/editions/community/docker-ce-desktop-windows
- Anaconda (strongly recommended): https://www.anaconda.com/distribution/
/
Make sure to add dep to path (typically this particular path)
C:\Program Files (x86)\GnuWin32\bin
-->

## Prerequisite
It is up to you whether you want to use the Clair binary (recommended) or install it from source on your local machine.

Clair binaries can be obtained here: https://github.com/arminc/clair-scanner/releases
1. Download the appropriate binary from the link above (e.g. for Ubuntu: clair-scanner_linux_amd64) using the following command:

        wget https://github.com/arminc/clair-scanner/releases/download/v8/clair-scanner_linux_amd64

2. Set write permission to the downloaded binary and move it to your home directory with the following name:

        chmod +x clair-scanner_linux_amd64
        mv clair-scanner_linux_amd64 $HOME/clair-scanner
    
3. Deploy the Clair database with the following command: 

        docker run -d --name db arminc/clair-db:latest

4. Deploy the Clair scanner with the following command:

        docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:latest

Important: make sure Clair scanner and the Clair database are using the "latest" tag, otherwise DAZER will try to delete them.

## Getting Started
1. Clone this repository

       git clone https://github.com/jonalu14/DAZER.git

2. Add your Docker Hub credentials to the credentials.yml file.
3. Navigate to its root directory and install all the necessary Python packages using the following command:

       pip install -e .
  
4. Run DAZER as followed:

       ./main.py <official|certified|verified|community> [<x_images>]
    
    Examples:  
    
		Gathering metadata and vulnerability information for all Certified images:

			./main.py certified
			
		Gathering metadata and vulnerability information for all Verified images:

			./main.py verified

		Gathering metadata and vulnerability information for all Official images:

			./main.py official

		Gathering metadata and vulnerability information for 100 random Community images among the most popular ones:

			./main.py community 100

4) Import the exported Json files to a noSQL database for further analysis (e.g. MonogDB):

        mongoimport --db analyzed_images --collection images --file $HOME/DAZER/DAZER/json/vulnerabilities_2019-02-19_14-58-00.json

## Downloads
An ova image (ubuntu_1604.ova) is provided if you do not want to install all the required tools.

## Demo
Pictures!

## Credits
DAZER integrates with Clair scanner (https://github.com/arminc/clair-scanner), an extension of the analyze-local-images tool by CoreOS (https://github.com/coreos/analyze-local-images), which enables quick analysis of local Docker images with the Clair software (https://github.com/coreos/clair). Note that Clair is an open source project for the static analysis of vulnerabilities in application containers developed by CoreOS and verifies vulnerabilities against a dedicated database updated daily.

## Licence
DAZER is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license description. 
