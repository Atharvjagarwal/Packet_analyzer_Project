# Windows Setup Guide

This project is a Java 25 Maven application. No C++ compiler or Python installation is required.

## Prerequisites

1. Install a Java Development Kit (JDK) 25 or newer.
2. Install Apache Maven 3.8 or newer and add its `bin` directory to `PATH`.
3. Open the project folder in PowerShell, Command Prompt, or VS Code.

Confirm Java and Maven are available:

```powershell
java -version
mvn -version
```

## Build and test

From the project root:

```powershell
mvn clean verify
```

This runs the tests and creates `target\packet-analyzer-1.0.0.jar`.

## Run the packet analyzer

Show command help:

```powershell
java -jar target\packet-analyzer-1.0.0.jar --help
```

Analyze a capture:

```powershell
java -jar target\packet-analyzer-1.0.0.jar output.pcap
java -jar target\packet-analyzer-1.0.0.jar output.pcap 100
```

## Run the DPI engine

```powershell
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.DpiEngine --help
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.DpiEngine output.pcap filtered_output.pcap --block-app YouTube --block-port 53 --report
```

The input and output PCAP paths must be different. The DPI engine creates a filtered copy and leaves the original capture unchanged.

## Generate a test capture

The Java test-capture generator creates synthetic traffic with TLS SNI, HTTP, DNS, and blocked-source examples:

```powershell
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.TestPcapGenerator generated_test.pcap
```

To choose another output path, provide it as the argument:

```powershell
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.TestPcapGenerator C:\temp\test_dpi.pcap
```

## VS Code

Open the project folder in VS Code and install the Java Extension Pack if prompted. Use the integrated terminal to run `mvn clean verify`.

## Troubleshooting

- **`java` is not recognized:** Install a JDK and add its `bin` directory to `PATH`.
- **`mvn` is not recognized:** Install Apache Maven and add its `bin` directory to `PATH`, then restart the terminal.
- **The analyzer cannot find a PCAP:** Check that the input path is correct and that the file is a supported PCAP capture.
- **`java -jar` reports that the jar cannot be found:** Run the build command from the project root and confirm `target\packet-analyzer-1.0.0.jar` exists.
