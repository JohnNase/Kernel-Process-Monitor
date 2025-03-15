# Linux Kernel Process Monitor

This project involves developing a Linux kernel module that monitors running processes on the system. The kernel module tracks process creation and termination events and stores relevant information (e.g., PID, process name, state). A user-space application retrieves this information from the kernel module and displays it in a structured format. This project showcases advanced kernel programming, process management, and user-kernel interaction.

## Features
- **Kernel Module**: Monitors process creation and termination events using kernel hooks.
- **Process Information Storage**: Stores process details (PID, name, state) in a kernel data structure.
- **User-Space Application**: Retrieves and displays process information from the kernel module.
- **Makefile**: Automates the compilation of the kernel module and user-space application.

## Technologies Used
- **C Programming**: For kernel module and user-space application development.
- **Linux Kernel APIs**: `task_struct`, `kprobes`, `procfs`, `seq_file`, etc.
- **Make**: For automating the build process.
- **Ubuntu/WSL**: Development environment.
