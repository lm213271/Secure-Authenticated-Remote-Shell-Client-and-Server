all:
	gcc RShellClient2.c -o RShellClient2 -lssl -lcrypto
	gcc RShellServer2.c -o RShellServer2 -lssl -lcrypto
clean:
	rm -rf RShellClient2
	rm -rf RShellServer2
