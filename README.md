### UFmyMusic Project

## Project Description
UFmyMusic is a networked application that synchronizes music files across multiple machines. It ensures that each machine has the same set of files in their music directory. The application allows the client to list files, find differences between client and server files, pull missing files from the server, and leave the system.

## Directory Structure
The project folder includes the following structure:

- `client_files`: Folder containing music files for the client.
- `server_files`: Folder containing music files for the server.
- `.gitignore`: File to ignore specific files in version control.
- `client.c`: Client-side source code.
- `server.c`: Server-side source code.
- `Makefile`: File to compile both client and server.

## Prerequisites
- A Linux-based or compatible system.
- A terminal to compile and run the program or Visual Studio Code.
- Installed `gcc` compiler.
- Installed `make` tool.

## Compilation Instructions
After making any changes to either `server.c` or `client.c`, follow these steps to compile the project:

1. Open a terminal in Visual Studio Code (VSCode).
2. Run the `make` command in the terminal to compile both the client and server programs. This will generate two executable files: `server` and `client`.

## Running the Server and Client
To test the project, you will need to open two separate terminal windows.

### Step 1: Running the Server
In the first terminal window, run the server using the command `./server`. This will start the server, which will listen for connections from clients.

### Step 2: Running the Client
In the second terminal window, run the client using the command `./client`. Once the client is running, a menu will appear on the client side with the following options:

- 1. LIST: Lists the files available on the server.
- 2. DIFF: Shows the differences between the client’s files and the server’s files.
- 3. PULL: Pulls missing files from the server to the client.
- 4. LEAVE: Exits the program.

Enter the appropriate number (1, 2, 3, or 4) that corresponds to function you want to run. Note that the output of DIFF is dependent on the output of LIST and PULL is dependent on the output of DIFF.

## Notes
- Ensure that both the server and client are running on the same network for proper communication.
- If you encounter any issues, ensure the port and network configurations are correctly set within the code.

## Cleaning Up
To remove the generated executables and clean the directory, you can run `make clean`.
